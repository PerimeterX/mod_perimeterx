FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y \
        apache2 \
        apache2-dev \
        build-essential \
        libcurl4-openssl-dev \
        libjansson-dev \
        libssl-dev \
        vim \
        git \
        pkg-config \
        silversearcher-ag

WORKDIR tmp
RUN git clone https://github.com/PerimeterX/mod_perimeterx.git
RUN cd mod_perimeterx && make
