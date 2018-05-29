FROM ubuntu:bionic
RUN mkdir /deb
RUN apt-get -qq update && apt-get -qq upgrade && apt-get install -y git devscripts equivs pkg-config
COPY . /libfido2
RUN rm -rf /libfido2/build
RUN yes | mk-build-deps -i /libfido2/debian/control
RUN cd /libfido2 && debuild -us -uc
RUN mv /libfido2* /deb
RUN tar czf /libfido2-debian-packages.tar.gz /deb
