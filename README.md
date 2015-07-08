# shibboleth-oidc
OpenIDConnect support for the Shibboleth Identity Provider version 3

[![Build Status](https://travis-ci.org/uchicago/shibboleth-oidc.svg?branch=master)](https://travis-ci.org/uchicago/shibboleth-oidc)

## Versions
- [Shibboleth Identity Provider v3.1.3-SNAPSHOT](https://wiki.shibboleth.net/confluence/display/IDP30/Home)
- Apache Maven v3.x
- JDK 8

## Build
In order to run the overlay build, examine the `/conf/idp.properties` inside the `idp-webapp-overlay` module,
and adjust the values of hostname, entityId, passwords, etc. Then from the command prompt, execute:

### Initial installs

```bash
mvn clean package -P new
```

This will wipe out any previous files inside `credentials` and `metadata` directories and start anew.


### Subsequent installs

```bash
mvn clean package
```

## Run
Navigate to the `idp-webapp-overlay` module and run the following command:

```bash
mvn verify
```

This will spin up an embedded Jetty server to load the IdP context. 

* Remote debugging is available under port 5000 from your IDE. 
* You will also need to set up a keystore under `/etc/jetty` and name it `thekeystore`
* The keystore password and the key password should both be `changeit`.
 
A sample keystore is provided under the `idp-webapp-overlay/etc/` directory that is empty, and can be used to set up the environment.  
