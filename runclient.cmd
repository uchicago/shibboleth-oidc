@echo off
mvn clean package jetty:run-forked -T 10 --projects simple-web-app
