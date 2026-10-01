# syntax=docker/dockerfile:1
# Build context: the repository root.
#   docker build -f deploy/Dockerfile -t tree-server .

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p tree-server \
 && cp target/release/tree-server /tree-server \
 && mkdir -p /data

# Small runtime image with only libc/libgcc, no shell, non-root user (uid 65532).
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /tree-server /usr/local/bin/tree-server
COPY --from=build --chown=65532:65532 /data /data
USER 65532:65532
ENV BIND_ADDR=0.0.0.0:8080 \
    DATABASE_URL=sqlite:///data/tree.db
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/tree-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/tree-server"]
