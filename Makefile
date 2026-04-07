.PHONY: all check test clippy fmt fmt-check lint ci clean publish

all: lint test

check:
	cargo check --all-features

test:
	cargo test --all-features

clippy:
	cargo clippy --all-features -- -D warnings

fmt:
	cargo fmt

fmt-check:
	cargo fmt -- --check

lint: clippy fmt-check

ci: lint test

clean:
	cargo clean

publish: ci
	cargo publish

help:
	@echo "Targets:"
	@echo "  all          lint + test (default)"
	@echo "  check        cargo check"
	@echo "  test         cargo test"
	@echo "  clippy       cargo clippy"
	@echo "  fmt          cargo fmt"
	@echo "  fmt-check    cargo fmt --check"
	@echo "  lint         clippy + fmt-check"
	@echo "  ci           lint + test"
	@echo "  publish      lint + test + cargo publish"
	@echo "  clean        cargo clean"
