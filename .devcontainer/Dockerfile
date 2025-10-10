FROM ubuntu:latest

# Install basic dependencies
RUN apt-get update && \
    apt-get install -y \
    curl \
    wget \
    git \
    ca-certificates \
    gnupg2 \
    jq \
    sudo \
    nano \
    vim \
    build-essential \
    openssl && \
    rm -rf /var/lib/apt/lists/*
