# hooksink image: a static musl binary on scratch. Build from the
# repository root. The build stage runs fmt, clippy and the tests first.
FROM docker.io/library/rust:1.90-alpine AS build
RUN apk add --no-cache gcc musl-dev \
    && rustup component add rustfmt clippy
WORKDIR /source

# Build the dependencies alone first, so a source-only change reuses them.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src tests \
    && echo 'fn main() {}' > src/main.rs \
    && touch src/lib.rs \
    && cargo build --locked --release \
    && cargo test --locked --no-run \
    && rm -rf src tests

COPY src ./src
COPY tests ./tests
# Cargo compares mtimes; make sure the real sources are newer than the stubs.
RUN touch src/main.rs src/lib.rs \
    && cargo fmt --all --check \
    && cargo clippy --locked --all-targets -- -D warnings \
    && cargo test --locked \
    && cargo build --locked --release \
    && mkdir -p /out/data \
    && cp target/release/hooksink /out/hooksink

FROM scratch
COPY --from=build /out/hooksink /hooksink
COPY --from=build --chown=1000:1000 /out/data /data
USER 1000:1000
ENV HOOKSINK_LISTEN=0.0.0.0:8080 \
    HOOKSINK_ADMIN_LISTEN=0.0.0.0:8081 \
    HOOKSINK_DB=/data/events.sqlite
# 8080: /hooks and consumer reads. 8081: admin console and API.
EXPOSE 8080 8081
ENTRYPOINT ["/hooksink"]
