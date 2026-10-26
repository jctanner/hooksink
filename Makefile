IMAGE ?= hooksink:latest
RUST_IMAGE ?= docker.io/library/rust:1.90-alpine
CONTAINER ?= $(shell command -v podman >/dev/null 2>&1 && echo podman || echo docker)

.PHONY: build test run image lint fmt

build: ## Debug build
	cargo build

test: ## Unit and HTTP tests
	cargo test

run: ## Run locally on :8080 with ./data/events.sqlite
	HOOKSINK_LISTEN=127.0.0.1:8080 HOOKSINK_DB=./data/events.sqlite cargo run

image: ## Container image; the build runs fmt, clippy and tests first
	$(CONTAINER) build -t $(IMAGE) .

lint: ## fmt check and clippy in the Rust image
	$(CONTAINER) run --rm -v "$(CURDIR)":/source:Z -w /source -e CARGO_TARGET_DIR=/tmp/target $(RUST_IMAGE) \
	  sh -c 'apk add -q --no-cache gcc musl-dev && rustup component add rustfmt clippy >/dev/null 2>&1 \
	         && cargo fmt --all --check && cargo clippy --locked --all-targets -- -D warnings'

fmt: ## Apply rustfmt in the Rust image
	$(CONTAINER) run --rm -v "$(CURDIR)":/source:Z -w /source $(RUST_IMAGE) \
	  sh -c 'rustup component add rustfmt >/dev/null 2>&1 && cargo fmt --all'
