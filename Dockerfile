FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl
COPY src ./src
RUN touch src/main.rs && cargo build --release --target x86_64-unknown-linux-musl

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/irondome /irondome

ENTRYPOINT ["/irondome"]
