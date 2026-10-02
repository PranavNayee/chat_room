'use strict';
/* All user-controlled text is inserted with textContent / createTextNode, never innerHTML. */
(() => {
  const $ = (id) => document.getElementById(id);
  const authScreen = $('auth-screen'), chatScreen = $('chat-screen');
  const GROUP = '';                       // conversation key of the group room

  const state = {
    me: null, ws: null, users: new Map(), convs: new Map(), current: GROUP,
    reconnectAttempts: 0, reconnectTimer: null, intentionalClose: false,
    typingTimers: new Map(), lastTypingSent: 0, authMode: 'login', filter: '',
  };

  /* ---------------- helpers ---------------- */
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg; t.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => { t.hidden = true; }, 4000);
  }
  function conv(key) {
    if (!state.convs.has(key)) state.convs.set(key, { msgs: [], loaded: false, unread: 0 });
    return state.convs.get(key);
  }
  function fmtTime(ts) {
    const d = new Date(ts), now = new Date();
    const t = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return d.toDateString() === now.toDateString() ? t : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + t;
  }
  async function api(path, body) {
    const res = await fetch(path, {
      method: body === undefined ? 'GET' : 'POST',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    });
    let data = {};
    try { data = await res.json(); } catch (_) { /* non-JSON error */ }
    return { ok: res.ok, status: res.status, data };
  }
  function send(obj) {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) { state.ws.send(JSON.stringify(obj)); return true; }
    return false;
  }

  /* ---------------- auth UI ---------------- */
  function showAuth() {
    state.intentionalClose = true;
    if (state.ws) state.ws.close();
    clearTimeout(state.reconnectTimer);
    chatScreen.hidden = true; authScreen.hidden = false;
    $('auth-password').value = '';
    $('auth-username').focus();
  }
  function setAuthMode(mode) {
    state.authMode = mode;
    const reg = mode === 'register';
    $('tab-login').classList.toggle('active', !reg);
    $('tab-register').classList.toggle('active', reg);
    $('auth-submit').textContent = reg ? 'Create account' : 'Log in';
    $('auth-password').autocomplete = reg ? 'new-password' : 'current-password';
    $('auth-hint').hidden = !reg;
    $('auth-error').hidden = true;
  }
  $('tab-login').addEventListener('click', () => setAuthMode('login'));
  $('tab-register').addEventListener('click', () => setAuthMode('register'));
  $('auth-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = $('auth-submit'), err = $('auth-error');
    btn.disabled = true; err.hidden = true;
    try {
      const r = await api(state.authMode === 'register' ? '/api/register' : '/api/login',
        { username: $('auth-username').value.trim(), password: $('auth-password').value });
      if (r.ok) { $('auth-password').value = ''; startChat(r.data.user); }
      else { err.textContent = r.data.error || 'Something went wrong'; err.hidden = false; }
    } catch (_) {
      err.textContent = 'Cannot reach the server'; err.hidden = false;
    } finally { btn.disabled = false; }
  });
  $('logout-btn').addEventListener('click', async () => {
    state.intentionalClose = true;
    try { await api('/api/logout', {}); } catch (_) { /* ignore */ }
    state.users.clear(); state.convs.clear(); state.me = null; state.current = GROUP;
    showAuth();
  });

  /* ---------------- websocket ---------------- */
  function startChat(user) {
    state.me = user;
    state.users.clear(); state.convs.clear(); state.current = GROUP;
    $('me-name').textContent = user;
    authScreen.hidden = true; chatScreen.hidden = false;
    renderAll();
    connect();
  }
  function connect() {
    state.intentionalClose = false;
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${location.host}/ws`);   // same host/port as the page
    state.ws = ws;
    setStatus('Connecting…', false);

    ws.onopen = () => { state.reconnectAttempts = 0; setStatus('Connected', true); };
    ws.onmessage = (ev) => {
      if (typeof ev.data !== 'string') return;
      let m; try { m = JSON.parse(ev.data); } catch (_) { return; }
      handle(m);
    };
    ws.onclose = async () => {
      if (state.ws !== ws || state.intentionalClose) return;
      setStatus('Disconnected — reconnecting…', false);
      // If the session is gone (expired / logged out elsewhere) go back to the login screen.
      try { const r = await api('/api/me'); if (r.status === 401) { toast('Session ended. Please log in again.'); showAuth(); return; } } catch (_) {}
      const delay = Math.min(1000 * 2 ** Math.min(state.reconnectAttempts++, 5), 30000);
      state.reconnectTimer = setTimeout(connect, delay);
    };
  }
  function setStatus(text, online) {
    $('status').textContent = text;
    $('me-dot').classList.toggle('on', online);
  }

  function handle(m) {
    switch (m.type) {
      case 'hello': state.me = m.user; $('me-name').textContent = m.user; break;
      case 'users':
        state.users = new Map(m.users.map((u) => [u.name, !!u.online]));
        renderSidebar();
        if (state.current !== GROUP) requestHistory(state.current);
        break;
      case 'presence':
        state.users.set(m.name, !!m.online);
        renderSidebar(); renderHeader();
        break;
      case 'history': {
        const c = conv(m.with);
        c.msgs = m.messages; c.loaded = true;
        if (m.with === state.current) renderMessages();
        break;
      }
      case 'msg': {
        const key = m.to === GROUP ? GROUP : (m.from === state.me ? m.to : m.from);
        const c = conv(key);
        if (key !== GROUP && !state.users.has(key)) state.users.set(key, true);
        c.msgs.push(m);
        if (c.msgs.length > 500) c.msgs.splice(0, c.msgs.length - 500);
        if (key === state.current) { renderMessages(); clearTyping(m.from); }
        else if (m.from !== state.me) { c.unread++; renderSidebar(); }
        break;
      }
      case 'typing': {
        const key = m.to === GROUP ? GROUP : m.from;
        if (key !== state.current) break;
        showTyping(m.from);
        break;
      }
      case 'error': toast(m.message || 'Error'); break;
    }
  }

  /* ---------------- conversations ---------------- */
  function requestHistory(key) { send({ type: 'history', with: key }); }
  function openConv(key) {
    state.current = key;
    const c = conv(key);
    c.unread = 0;
    if (!c.loaded || key !== GROUP) requestHistory(key);
    $('typing').textContent = '';
    renderAll();
    $('sidebar').classList.remove('open');
    $('msg-input').focus();
  }

  /* ---------------- rendering ---------------- */
  function convButton(key, label, online, unread) {
    const li = document.createElement('li');
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'conv' + (key === state.current ? ' active' : '');
    if (online !== null) { const d = document.createElement('span'); d.className = 'dot' + (online ? ' on' : ''); b.appendChild(d); }
    const n = document.createElement('span'); n.className = 'name'; n.textContent = label; b.appendChild(n);
    if (unread > 0) { const u = document.createElement('span'); u.className = 'badge'; u.textContent = String(unread); b.appendChild(u); }
    b.addEventListener('click', () => openConv(key));
    li.appendChild(b);
    return li;
  }
  function renderSidebar() {
    const rooms = $('room-list'); rooms.textContent = '';
    rooms.appendChild(convButton(GROUP, '# General', null, conv(GROUP).unread));

    const list = $('user-list'); list.textContent = '';
    const q = state.filter.toLowerCase();
    const people = [...state.users.entries()]
      .filter(([n]) => n !== state.me && n.toLowerCase().includes(q))
      .sort((a, b) => (b[1] - a[1]) || a[0].localeCompare(b[0], undefined, { sensitivity: 'base' }));
    if (!people.length) {
      const li = document.createElement('li'); li.className = 'empty';
      li.textContent = q ? 'No matches' : 'No other users yet'; list.appendChild(li);
    }
    for (const [name, online] of people) list.appendChild(convButton(name, name, online, conv(name).unread));
  }
  function renderHeader() {
    if (state.current === GROUP) {
      $('conv-title').textContent = '# General';
      const online = [...state.users.values()].filter(Boolean).length;
      $('conv-sub').textContent = `Group chat · ${online} online`;
    } else {
      $('conv-title').textContent = state.current;
      $('conv-sub').textContent = state.users.get(state.current) ? 'Online · private chat' : 'Offline · private chat';
    }
    $('msg-input').placeholder = state.current === GROUP ? 'Message everyone' : `Message ${state.current}`;
  }
  function renderMessages() {
    const box = $('messages');
    box.textContent = '';
    const c = conv(state.current);
    if (!c.msgs.length) {
      const d = document.createElement('div'); d.className = 'sys';
      d.textContent = state.current === GROUP ? 'No messages yet. Say hello!' : `This is the start of your private chat with ${state.current}.`;
      box.appendChild(d);
    }
    for (const m of c.msgs) {
      const mine = m.from === state.me;
      const el = document.createElement('div');
      el.className = 'msg' + (mine ? ' mine' : '');
      if (!mine && state.current === GROUP) {
        const w = document.createElement('span'); w.className = 'who'; w.textContent = m.from; el.appendChild(w);
      }
      el.appendChild(document.createTextNode(m.text));
      const t = document.createElement('span'); t.className = 'time'; t.textContent = fmtTime(m.ts); el.appendChild(t);
      box.appendChild(el);
    }
    box.scrollTop = box.scrollHeight;
  }
  function renderAll() { renderSidebar(); renderHeader(); renderMessages(); }

  /* ---------------- typing indicator ---------------- */
  function showTyping(from) {
    clearTimeout(state.typingTimers.get(from));
    state.typingTimers.set(from, setTimeout(() => clearTyping(from), 3000));
    updateTyping();
  }
  function clearTyping(from) { clearTimeout(state.typingTimers.get(from)); state.typingTimers.delete(from); updateTyping(); }
  function updateTyping() {
    const names = [...state.typingTimers.keys()];
    $('typing').textContent = !names.length ? '' : names.length === 1 ? `${names[0]} is typing…` : 'Several people are typing…';
  }

  /* ---------------- composer ---------------- */
  $('msg-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const input = $('msg-input');
    const text = input.value.trim();
    if (!text) return;
    if (send({ type: 'msg', to: state.current, text })) input.value = '';
    else toast('Not connected. Reconnecting…');
  });
  $('msg-input').addEventListener('input', () => {
    const now = Date.now();
    if (now - state.lastTypingSent > 2000) { state.lastTypingSent = now; send({ type: 'typing', to: state.current }); }
  });
  $('user-filter').addEventListener('input', (e) => { state.filter = e.target.value; renderSidebar(); });
  $('menu-btn').addEventListener('click', () => $('sidebar').classList.toggle('open'));

  /* ---------------- boot ---------------- */
  (async () => {
    try {
      const r = await api('/api/me');
      if (r.ok) { startChat(r.data.user); return; }
    } catch (_) { /* fall through to login */ }
    authScreen.hidden = false;
    $('auth-username').focus();
  })();
})();
