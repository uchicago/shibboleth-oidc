#!/usr/bin/env bash
mvn clean package verify -Dhost=jetty --projects idp-oidc-impl,idp-webapp-overlay
