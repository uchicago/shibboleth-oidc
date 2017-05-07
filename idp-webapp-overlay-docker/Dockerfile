FROM centos:centos7

MAINTAINER Misagh Moayyed

RUN yum install -y java-devel which wget

COPY idp /opt/shibboleth-idp

WORKDIR /opt/shibboleth-idp

RUN chmod +x mvnw 

RUN mkdir /etc/jetty \
    && cp etc/jetty/thekeystore /etc/jetty/thekeystore

EXPOSE 8443

CMD export JAVA_HOME=$(readlink -f /usr/bin/javac | sed "s:/bin/javac::"); ./runidp.sh