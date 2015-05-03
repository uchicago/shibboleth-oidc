# Shibboleth Identity Provider Web Application
The [Shibboleth Identity Provider](https://shibboleth.net) web application built using Apache Maven.

## Changes
- The IdP is configured to load all configuration from the classpath. In a sense, the `$IDP_HOME` directory is configured to be at `src/main/resources`.
- The IdP is configured to use a CAS server for authentication and SSO via the [Shib-CAS Authenticator v3](https://github.com/unicon/shib-cas-authn3)

## Version
- [Shibboleth Identity Provider v3.1.1](https://wiki.shibboleth.net/confluence/display/IDP30/Home)

## Build Status
* [![Build Status](https://secure.travis-ci.org/UniconLabs/shibboleth-idp-webapp.png)](http://travis-ci.org/UniconLabs/shibboleth-idp-webapp)
