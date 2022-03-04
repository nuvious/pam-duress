FROM ubuntu:latest

RUN apt-get update -y
RUN apt-get install build-essential libpam0g-dev autoconf automake libtool pkg-config -y

COPY . /dev
WORKDIR /dev

RUN make clean
RUN make
RUN make install

CMD /bin/bash
