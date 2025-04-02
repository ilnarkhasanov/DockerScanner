FROM ubuntu:20.04
RUN apt-get update && apt-get install -y wget build-essential && rm -rf /var/lib/apt/lists/*
RUN wget https://www.openssl.org/source/openssl-1.0.1e.tar.gz \
    && tar -xzvf openssl-1.0.1e.tar.gz \
    && cd openssl-1.0.1e \
    && ./config && make && make install \
    && cd .. && rm -rf openssl-1.0.1e openssl-1.0.1e.tar.gz

