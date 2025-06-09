FROM rustlang/rust:nightly
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    clang \
    vim \
    pkg-config \ 
    libssl-dev \ 
    && rm -rf /var/lib/apt/lists/*
RUN update-alternatives --install /usr/bin/cc cc /usr/bin/clang 100 \
        && update-alternatives --install /usr/bin/c++ c++ /usr/bin/clang++ 100