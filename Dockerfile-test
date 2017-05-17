FROM ubuntu:16.04

MAINTAINER aviad@perimeterx.com

ADD *.sh /home/r/

RUN bash /home/r/docker-test-entry.sh

RUN apt-get update && apt-get install -y \
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
    libapache2-mod-perl2 \
    libjson0 \
    libjson0-dev \
    cpanminus

WORKDIR /home/r

RUN cpanm Apache::Test Crypt::KeyDerivation

RUN git clone https://github.com/PerimeterX/mod_perimeterx.git && cd ./mod_perimeterx
RUN chown -R r /home/r

RUN cd mod_perimeterx && perl Makefile.PL && make && make install
RUN cd mod_perimeterx/src && make debug && make install

#CMD ["su", "-m", "r" , "-c"  , "/home/r/mod_perimeterx/t/TEST"]
CMD ["su", "-m", "r" , "-c"  , "bash /home/r/run-test.sh"]
#CMD ["bash"]
