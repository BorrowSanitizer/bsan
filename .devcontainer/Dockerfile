# syntax=docker/dockerfile:1
FROM ubuntu:24.04 AS base
ENV DEBIAN_FRONTEND=noninteractive
ENV RUSTUP_HOME=/root/.rustup \
    CARGO_HOME=/root/.cargo \
    XDG_CACHE_HOME=/root/.cache

RUN apt-get update && apt-get install -y \
    gh \
    build-essential \
    cmake \
    clang \
    clang-tidy \
    clang-format \
    ninja-build \
    curl \
    vim \
    wget \
    ca-certificates \
    pkg-config \
    libssl-dev \
    libunwind-dev \
    jq \
    hyperfine \
    sudo \
    git \
    gdb \
    && rm -rf /var/lib/apt/lists/*

# Install GitHub CLI
RUN mkdir -p -m 755 /etc/apt/keyrings \
    && wget -nv -O /etc/apt/keyrings/githubcli-archive-keyring.gpg \
       https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
       > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

RUN update-alternatives --install /usr/bin/cc cc /usr/bin/clang 100 \
    && update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++ 100
    
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain nightly -y
ENV PATH="/root/.cargo/bin:${PATH}"

FROM base AS build-image-dev
RUN mkdir /build-xb
COPY bsan-script /build-xb/bsan-script
COPY config.toml /build-xb/
COPY xb /build-xb/
WORKDIR /build-xb
RUN ./xb --skip setup

FROM base AS image-dev
COPY --from=build-image-dev /root/.rustup/toolchains/bsan /root/.rustup/toolchains/bsan
COPY --from=build-image-dev /root/.cargo/ /root/.cargo

FROM base AS build-image-release
RUN --mount=type=bind,target=/bsan,rw \
    cd /bsan \
    && ./xb install

FROM base AS image-release
COPY --from=build-image-release /root/.rustup/toolchains/bsan /root/.rustup/toolchains/bsan
COPY --from=build-image-release /root/.cargo/bin /root/.cargo/bin
RUN rustup default bsan && rustc -vV
