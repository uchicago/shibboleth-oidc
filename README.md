# Shibboleth Identity Provider Web Application
The [Shibboleth Identity Provider](https://shibboleth.net) web application built using Apache Maven.


> This project was developed as part of Unicon's [Open Source Support program](https://unicon.net/opensource).
Professional Support / Integration Assistance for this module is available. For more information [visit](https://unicon.net/opensource/cas).


## Goals
The objective of this project is to demonstrate that the Shibboleth Identity Provider can be deployed via a Maven overlay mechanism. In this approach, the build is driven by not the Shibboleth IdP's installer and/or ant, but entirely by Maven. The following goals and benefits are considered:

1. A Maven overlay mechanism allows one to only keep customized configuration and artifacts. Everything else is retrieved and packaged by Maven.
2. A Maven overlay mechanism attempts to "hide" some of the more system-level configuration files that are not immediately required for user modifications.
3. The upgrade process for patches and minor releases can be very comfortable by simply modifying pom versions.
4. The size of the Maven overlay installation packaged is considerably reduced.
5. A Maven overlay easily allows one to extend the IdP's Java classes. Developed extensions are compiled via Maven and added to the classpath.
6. A Maven overlay allows one to override the existing IdP Java `final` classes. A copy of the class may be placed at the exact package path, which will be compiled via Maven, added to classpath and used before the original component by the classloader.

## Tread Lightly
1. Redeployments are required for changes, because the IdP runtime is modified to not point to an external location outside the webapp,
as it did previously with references to `/opt/shibboleth-idp` for instance by default, but inside its own context. Therefore, any changes that are applied to a local overlay
need to redeployed and repackaged to be included in the same webapp.

2. Overlaying can be confusing, because components are not immediately available for modifications should they be needed. A deployer
would have to find a way to place the to-be-overlaid file at the exact path in order for the entire process to work. Good documentation
can be instrumental in this case. In such cases, starting with a brand new overlay and gradually porting configuration over is the recommended
approach.

3. Upgrades can be difficult if there are A LOT of extensive local modifications to the overlay. A deployer would have to cross-compare
their local changes with that of the original bundle to ensure they are not missing or going to break anything.

4. A local Maven installation is required for the build. (Gradle can make this problem go away as it will know how to install and configure itself)

## Modules
This project is comprised of the following modules:

### idp-webapp
The base Shibboleth Identity Provider. Here are the differences with the original IdP:

1. The `$IDP_HOME` directory is moved to `src/main/webapp/idp`. This includes all of the configuration required to run the IdP by default with the exception of `credentials` and `metadata`.
2. The IdP is configured to initialize its configuration from the above location.

Moving the configuration to the IdP web application itself allows the final `war` artifact to become available for overlays. Deployers can then pick and choose what they need to include
in their own overlay and redeploy the application. In practice, the produced `war` artifact would be released into some sort of remote Maven repository.

### idp-webapp-support
A utility module, at this point mostly to help with generation of IdP's metadata from command-line via `MetadataGeneratorTool`.
This module is used by the overlay in order to fully complete the installation.

### idp-webapp-overlay
A maven overlay module that attempts to download the `idp-webapp` (i.e. from a remote maven repository, which will be cached into a local)
and overlay its own configuration on top of it. These include changes for attribute resolution and release,
providing metadata, CAS authentication and so on.

Note that deployers are entirely responsible for this module. The sample that is provided here
attempts to fully complete the idp installation process by generating the needed keystores, certs and metadata.

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

### Artifact Signature Verification
Given that maven itself is unable to verify artifact signatures, a profile is developed to take advantage of the
`pgpverify-maven-plugin` plugin, to ensure all artifacts are legitimate. Those that fail the verification step will
cause the build to fail.


```bash
mvn clean package -P pgp
```

Note that dependency resolution is only limited to the following repositories:

```bash
- Releases: https://build.shibboleth.net/nexus/content/groups/public
- Snapshots: https://build.shibboleth.net/nexus/content/repositories/snapshots
```

Maven central is turned off.

## Run
Navigate to the `idp-webapp-overlay` module and run the following command:

```bash
mvn validate
```

This will spin up an embedded Jetty server to load the IdP context. Remote debugging
is available under port 5000 from your IDE.

## Versions
- [Shibboleth Identity Provider v3.1.3-SNAPSHOT](https://wiki.shibboleth.net/confluence/display/IDP30/Home)
- Apache Maven v3 (required)
- JDK 8 (required)

## Build Status
* [![Build Status](https://secure.travis-ci.org/UniconLabs/shibboleth-idp-webapp.png)](http://travis-ci.org/UniconLabs/shibboleth-idp-webapp)
