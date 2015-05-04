# Shibboleth Identity Provider Web Application
The [Shibboleth Identity Provider](https://shibboleth.net) web application built using Apache Maven.

## Goals
The objective of this project is to demonstrate that the Shibboleth Identity Provider can be deployed via a Maven overlay mechanism. In this approach, the build is driven by not the Shibboleth IdP's installer and/or ant, but entirely by Maven. The following goals and benefits are considered:

1. A Maven overlay mechanism allows one to only keep customized configuration and artifacts. Everything else is retrieved and packaged by Maven.
2. A Maven overlay mechanism attempts to "hide" some of the more system-level configuration files that are not immediately required for user modifications.
3. The upgrade process for patches and minor releases can be very comfortable by simply modifying pom versions.
4. The size of the Maven overlay installation packaged is considerably reduced.

## Tread Lightly
1. Redeployments are required for changes, because the IdP runtime is modified to not point to an external location outside the webapp,
as it did previously with references to `/opt/shibboleth-idp` for instance by default, but inside its own context. Therefore, any changes that are applied to a local overlay
need to redeployed and repackaged to be included in the same webapp. 

2. Overlaying can be confusing, because components are not immediately available for modifications should they be needed. A deployer
would have to find a way to place the to-be-overlaid file at the exact path in order for the entire process to work. Good documentation
can be instrumental in this case. 

3. Upgrades can be difficult if there are A LOT of extensive local modifications to the overlay. A deployer would have to cross-compare
their local changes with that of the original bundle to ensure they are not missing or going to break anything.

4. A local Maven installation is required for the build. (Gradle can make this problem go away as it will know how to install and configure itself) 

## Modules
This project is comprised the following modules:

### idp-webapp
The base Shibboleth Identity Provider. Here are the differences with the original IdP:

1. The IdP includes the necessary changes to integrate with a given CAS server for authentication, but does *NOT* enable that flow. 
2. The `$IDP_HOME` directory is moved to `src/main/webapp/idp`. This includes all of the configuration required to run the IdP by default with the exception of `credentials` and `metadata`.
3. The IdP is configured to initialize its configuration from the above location.

Moving the configuration to the IdP web application itself allows the final `war` artifact to become available for overlays. Deployers can then pick and choose what they need to include
in their own overlay and redeploy the application. In practice, the produced `war` artifact would be released into some sort of central Maven repository. 
 
### idp-webapp-support
A utility module, at this point mostly to help with generation of IdP's metadata from command-line via `MetadataGeneratorTool`.
This module is used by the overlay in order to fully complete the installation.

### idp-webapp-overlay
A maven overlay module that attempts to download the `idp-webapp` (i.e. from a central/local maven repository)
and overlay his/her own configuration on top of it. These include changes for attribute resolution and release,
providing metadata, CAS authentication and so on.

Note that deployers are entirely responsible for this module. The sample that is provided here
attempts to fully complete the idp installation process by generating the needed keystores, certs and metadata.

## Run
In order to run the overlay build, examine the `/conf/idp.properties` inside the `idp-webapp-overlay` module,
and adjust the values of hostname, entityId, passwords, etc. Then from the command prompt, execute:

```bash
mvn clean package

```

The final artifact from `idp-webapp-overlay/target/idp.war` will be at your service.

## Versions
- [Shibboleth Identity Provider v3.1.1](https://wiki.shibboleth.net/confluence/display/IDP30/Home)
- Apache Maven v3 (required)
- JDK 7 (required)

## Build Status
* [![Build Status](https://secure.travis-ci.org/UniconLabs/shibboleth-idp-webapp.png)](http://travis-ci.org/UniconLabs/shibboleth-idp-webapp)
