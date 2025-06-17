ARG TAG=latest
FROM ghcr.io/borrowsanitizer/rust:$TAG AS image-dev
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
    && rm -rf /var/lib/apt/lists/*
RUN update-alternatives --install /usr/bin/cc cc /usr/bin/clang 100 \
    && update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++ 100

FROM image-dev AS build-release
COPY . . 
RUN ./xb install

FROM image-dev AS image-release
COPY --from=build-release /root/.rustup/toolchains/bsan /root/.rustup/toolchains/bsan
COPY --from=build-release /root/.cargo/ /root/.cargo

RUN rustup default bsan && rustc -vV