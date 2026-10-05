# syntax=docker/dockerfile:1
# All benchmark jobs triggered by `bench.yml` run within this image. 
# It's based off the nightly release image, but it has BorrowSanitizer
# rebuilt from a particular commit being benchmarked. A version of this
# container is built once per each commit and target. This save considerable
# time in benchmarking. Otherwise, every one of the >100 runs would need
# to rebuild our toolchain. 
ARG BASE=ghcr.io/borrowsanitizer/bsan:latest
FROM ${BASE}

# The source is only mounted for the build, and the build
# and cargo caches are dropped in the same step. This ensures
# that there's only two layers added onto the base image. One
# contains the artifacts changed by `xb install`, and the other
# contains the instrumented sysroot. 
RUN --mount=type=bind,target=/bsan,rw \
    cd /bsan \
    && ./xb install \
    && rm -rf /root/.cargo/registry /root/.cargo/git

# We also want to build a sysroot. 
RUN cargo bsan setup || true