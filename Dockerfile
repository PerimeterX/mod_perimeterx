FROM debian:jessie

MAINTAINER aviad@perimeterx.com

RUN apt-get update
RUN apt-get install -y \
        apache2 \
        apache2-dev \
        wget \
        build-essential \
        libcurl4-openssl-dev \
        libjansson-dev \
        libssl-dev \
        vim \
        git \
        pkg-config \
        silversearcher-ag \
        libperl-dev \
        libgdm-dev \
        cpanminus \
        libjson0 \
        libjson0-dev \
        devscripts

WORKDIR tmp
RUN git clone https://github.com/PerimeterX/mod_perimeterx.git
RUN cd mod_perimeterx/src && make && make install

EXPOSE 80

#Make sure you have your perimeterx.conf in the build directory
ADD perimeterx.conf /etc/apache2/mods-available/perimeterx.conf
RUN ln -s /etc/apache2/mods-available/perimeterx.conf /etc/apache2/mods-enabled/
CMD ["apachectl", "-f", "/etc/apache2/apache2.conf", "-e", "debug", "-DFOREGROUND"]
