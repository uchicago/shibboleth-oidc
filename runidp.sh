#!/usr/bin/env bash
./mvnw clean package verify -Dhost=jetty --projects idp-oidc-impl,idp-webapp-overlay
