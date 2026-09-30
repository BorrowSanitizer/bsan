# syntax=docker/dockerfile:1
# The image every benchmark job in bench.yml runs in: the nightly release image
# with BorrowSanitizer rebuilt and installed from the commit being benchmarked.
#
# Built once per commit and target, so that each of the many per-crate bench
# jobs starts with BorrowSanitizer already installed instead of running
# `./xb install` itself. The source is only mounted for the build, and the build
# and cargo caches are dropped in the same step, so the one layer this adds on
# top of the base holds just what `xb install` changed; the base's layers are
# the ones every job already pulls.
ARG BASE=ghcr.io/borrowsanitizer/bsan:latest
FROM ${BASE}

RUN apt-get update && apt-get install -y hyperfine jq && rm -rf /var/lib/apt/lists/*

# GitHub Actions runs a container job with HOME=/github/home, but the toolchain
# lives under /root; point rustup, cargo and caches there directly.
ENV RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    XDG_CACHE_HOME=/root/.cache

RUN --mount=type=bind,target=/bsan,rw \
    cd /bsan \
    && ./xb install \
    && rm -rf /root/.cargo/registry /root/.cargo/git

# cargo-bsan builds an instrumented standard library on first use and caches
# it; build it here so every job does not build its own. Best-effort: a job
# whose cache does not match simply builds its own.
RUN cargo bsan setup || true
