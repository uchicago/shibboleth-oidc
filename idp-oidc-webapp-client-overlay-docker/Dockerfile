FROM centos:centos7

MAINTAINER Misagh Moayyed

RUN yum install -y java-devel which wget

COPY client /opt/shibboleth-idp-client

WORKDIR /opt/shibboleth-idp-client

RUN chmod +x mvnw 

RUN mkdir /etc/jetty \
    && cp etc/jetty/thekeystore /etc/jetty/thekeystore

EXPOSE 9443

CMD export JAVA_HOME=$(readlink -f /usr/bin/javac | sed "s:/bin/javac::"); ./runclient.sh