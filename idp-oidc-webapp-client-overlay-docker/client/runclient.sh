#!/usr/bin/env bash

export JAVA_HOME=$(readlink -f /usr/bin/javac | sed "s:/bin/javac::")

echo "**************************"
echo "JAVA_HOME: $JAVA_HOME"
echo "*******************************"

echo "Exporting certificate"
keytool -export -file idptestbedhttpdproxy -keystore /etc/jetty/thekeystore -alias idptestbedhttpdproxy

echo "Importing certificate"
keytool -import -file idptestbedhttpdproxy -keystore $JAVA_HOME/jre/lib/security/cacerts -alias idptestbed -storepass changeit  -noprompt

./mvnw clean package jetty:run-forked