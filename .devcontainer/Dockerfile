FROM ubuntu:latest AS base
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    ninja-build \ 
    clang \
    curl \ 
    vim \
    pkg-config \ 
    libssl-dev \ 
    sudo \
    git \
    && rm -rf /var/lib/apt/lists/*
RUN update-alternatives --install /usr/bin/cc cc /usr/bin/clang 100 \
    && update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++ 100
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --default-toolchain nightly -y
ENV PATH="/root/.cargo/bin:${PATH}"

FROM base AS build-image-dev
COPY . . 
RUN ./xb --skip setup

FROM base as image-dev
COPY --from=build-image-dev /root/.rustup/toolchains/bsan /root/.rustup/toolchains/bsan
COPY --from=build-image-dev /root/.cargo/ /root/.cargo

FROM image-dev AS build-image-release
RUN ./xb install

FROM base AS image-release
COPY --from=build-image-release /root/.rustup/toolchains/bsan /root/.rustup/toolchains/bsan
COPY --from=build-image-release /root/.cargo/ /root/.cargo
RUN rustup default bsan && rustc -vV