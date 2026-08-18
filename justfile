# The verb contract of netray-common (pdt-adlc ADR 0008).
#
# Migrated from a Makefile on 2026-08-19, by reduction: four of 11 targets are
# gone — help (`just --list` builds the listing, and the old help was a hand
# maintained echo block that had to be edited twice per change), all and ci
# (both were lint + test, which is what the contract calls `check`), and the
# old `check`, which was `cargo check`: a compile with no test run, and the
# name the ADLC resolver prefers — so every attestation this repository
# produced proved only that the code compiles (pdt-adlc backlog I14).
#
# This is a library: no frontend, no binary, nothing to serve. So adlc-verify
# and check are the same set, and `publish` is the one verb that must stay out
# of both — a gate must not publish (repo-contract).

cargo := "cargo"

default: adlc-verify

# --- the contract ------------------------------------------------------------

# What the ADLC gate runs: fmt-check, clippy, the suite. All offline.
adlc-verify: lint test

# Identical to adlc-verify: a library has nothing slower to separate out.
check: adlc-verify

# The suite, all features.
test:
    {{cargo}} test --all-features

# clippy + fmt-check.
lint: clippy fmt-check

# --- the individual checks ---------------------------------------------------

clippy:
    {{cargo}} clippy --all-features -- -D warnings

fmt-check:
    {{cargo}} fmt -- --check

fmt:
    {{cargo}} fmt

clean:
    {{cargo}} clean

# --- release -----------------------------------------------------------------

# Publish to crates.io. Reachable from no gate, by contract.
publish: check
    {{cargo}} publish
