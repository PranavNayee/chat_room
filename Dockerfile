# ---- build stage ----
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Makefile ./
COPY src ./src
RUN make chat_server

# ---- runtime stage ----
FROM debian:bookworm-slim
RUN useradd --system --no-create-home --shell /usr/sbin/nologin chat \
    && mkdir -p /app /var/data
WORKDIR /app
COPY --from=build /src/chat_server ./chat_server
COPY public ./public
COPY docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x docker-entrypoint.sh
ENV PORT=10000 DATA_DIR=/var/data
EXPOSE 10000
# Starts as root only to fix ownership of a mounted disk, then drops to the unprivileged user.
ENTRYPOINT ["./docker-entrypoint.sh"]
