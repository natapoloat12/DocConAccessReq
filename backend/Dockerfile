FROM rustlang/rust:nightly-slim as builder

WORKDIR /usr/src/app
COPY . .

# Build for release using nightly for edition2024 and unstable features
RUN cargo build --release

# Final Stage
FROM debian:bookworm-slim

WORKDIR /usr/local/bin
COPY --from=builder /usr/src/app/target/release/firewall-request-backend .

# Copy CA-certs from builder
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

EXPOSE 3000
CMD ["./firewall-request-backend"]
