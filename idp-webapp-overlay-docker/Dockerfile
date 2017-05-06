FROM centos:centos7

MAINTAINER Misagh Moayyed

RUN yum install -y java-devel which

COPY idp /opt/shibboleth-idp

WORKDIR /opt/shibboleth-idp

RUN chmod +x mvnw 

CMD export JAVA_HOME=$(readlink -f /usr/bin/javac | sed "s:/bin/javac::"); ./runidp.sh