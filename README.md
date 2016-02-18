# OpenId Connect for Shibboleth Identity Provider v3 [![License](https://img.shields.io/hexpm/l/plug.svg)](https://github.com/uchicago/shibboleth-oidc/blob/master/LICENSE) 
[![](https://heroku-badge.herokuapp.com/?app=shibboleth-oidc)](https://shibboleth-oidc.herokuapp.com/idp)
OpenIDConnect support for the Shibboleth Identity Provider version 3

## Contents
- [Scope](#scope)
- [Design](#design)
- [Default IdP Configuration](#default-idp-configuration)
- [Overlay IdP Configuration](#overlay-idp-configuration)

## Scope
We are working on adding support for the OpenID Connect protocol to the Shibboleth Identity Provider v3. Realistically, these
are the items we are planning to address:

* Authorization code workflow
* Dynamic discovery
* Administration and registration of OIDC RPs with the IdP. 
* Ability to resolve, consume and release OIDC claims, taking advantage of IdP's machinery to release attributes. 
* Ability to configure an expiration and revocation policy around OIDC access and refresh tokens from an admin perspective. 

Note that no significant UI enhancements are taken into account. All configuration and changes are directly assumed to be applied to the 
IdP config without the presence of a web interface to facilitate. This includes administration and management of metadata, 
authZ codes and more.

### Resources
* http://openid.net/specs/openid-connect-basic-1_0.html
* http://openid.net/specs/openid-connect-implicit-1_0.html
 
### Planned

The following may be considered in future versions:

* Implicit flow
* Hybrid flow
* Dynamic RP registration
* Logout
* Web UIs that facilitate managing tokens, whitelisted/blacklisted RPs, etc. 

### Toolkit
- Apache Maven v3.3+
- JDK 7+
- [MITREid Connect](https://github.com/mitreid-connect/) handles the OIDC implementation.
- [Shibboleth Identity Provider v3.2.1](https://wiki.shibboleth.net/confluence/display/IDP30/Home)
- [Modified test client application from MITREid Connect](https://github.com/mmoayyed/simple-web-app)

## Design
The OIDC support is provided via the [MITREid Connect](https://github.com/mitreid-connect/) project. It is itself based on Spring Security OAuth which itself in turn is based on Spring Security. So, the design principal of this extension is to mostly adapt the above frameworks to what the Shibboleth IdP framework provides in terms of authentication and attribute resolution. Also note that that MITREid Connect is entirely Spring annotations-based when it comes to wiring up the components. Spring Security OAuth also uses various annotations to respond to endpoint requests. Such changes also need to be accounted for in the IdP as it does not presently use a native model for annotation-based configuration of components. 

### Endpoints

The following endpoints are exposed by this extension:

- `/idp/profile/oidc/token`
- `/idp/profile/oidc/authorize`
- `/idp/profile/oidc/jwk`
- `/idp/profile/oidc/userinfo`
- `/idp/.well-known`

Each of these endpoints is protected via Spring Security, and configured in `oidc-protocol-endpoints.xml`. Spring Security OAuth itself presents various components that respond to framework endpoints and handles the OAuth functionality. In this extension, these endpoints are merely registered to note the new URL endpoint within the IdP framework. 

### Storage
MITREid Connect ships with a JPA implementation already that is responsible for managing the persistence of various tokens and the configuration of available/supported scopes, clients, etc. This extension leverages that functionality and configures a by-default inmemory database instance inside `oidc-protocol-storage.xml`. The database choice and driver are controllable via IdP settings inside `oidc.properties`. 

```properties
oidc.db.schema=%{idp.home}/conf/schema.sql
oidc.db.driver=org.hsqldb.jdbcDriver
oidc.db.url=jdbc:hsqldb:mem:oic;sql.syntax_mys=true
oidc.db.uid=sa
oidc.db.psw=
```

The following differences are to be noted:

#### System Scopes
Systems scopes are directly provided in the IdP configuration inside the `oidc-protocol.xml`. An adopter may choose to ignore/remove scopes that are deemed unsupported. 

#### Clients
Registration of clients is now directly provided in the IdP configuration inside the `oidc-protocol.xml`. 

### Issuer
The OIDC issuer is controlled via the `oidc.properties` file:

```properties
oidc.issuer=
```

This is used directly in the IdP configuration inside the `oidc-protocol.xml`. 

### System

There are various other authentication manager/provider components registered in `oidc-protocol-system.xml` that handle backchannel authentication requests for tokens and userinfo data. These are primarily based on Spring Security and MITREid Connect extensions of Spring Security. Additionally, auto-registration of MITREid Connect annotation-aware components  as well as all other components registered in this extension is handled here. 

### Encrytion/Signing
This extension ships with a default encryption/signing components defined in the `oidc-protocol-system.xml`. A default JWKS is also provided which can be controlled via `oidc.properties` at:

```properties
oidc.jwtset.keystore=%{idp.home}/credentials/keystore.jwks
```

This file is presently not reloaded on changes, and its associated context is also not yet reloadable. Key rotations for the default keystore must happen manually, and require a restart for the time being. 

Note that every client registered in the IdP is also able to specify an endpoint for its JWKS. 

### Claims
Claims can be configured as normal attribute definitions in the IdP. All standard claims that are present in the specification 
are supported. Here is an example of a claim:

```xml
<resolver:AttributeDefinition xsi:type="ad:Simple" id="family_name" sourceAttributeID="family_name">
    <resolver:Dependency ref="staticAttributes" />
    <resolver:DisplayName>Family Name</resolver:DisplayName>
</resolver:AttributeDefinition>
```

Note that attribute encoders are not needed since the JSON transformation is handled directly via the underlying frameworks. Also, claims can be filtered in turn by the IdP itself via the normal attribute filtering policy. Here is an example:

```xml
<AttributeFilterPolicy id="default">
    <PolicyRequirementRule xsi:type="Requester" value="client" />
    
    <AttributeRule attributeID="family_name">
        <PermitValueRule xsi:type="ANY" />
    </AttributeRule>
</AttributeFilterPolicy>
```

The requester (i.e. EntityID) is always the `clientId` of the client registered in the IdP.

Note that each client is able to specify which scopes it supports. This allows a second level of granularity where an adopter may choose to support only specific claims within a system scope. 

### Flows

#### Authorization Code Flow
This extension registered an authentication flow for OIDC inside `oidc/login/login-flow.xml` whose beans are configured inside `oidc/login/login-beans.xml`. A typical walkthrough of the authentication flow is as such:

- The client makes a request to `/idp/.well-known` to discover endpoints for OIDC conversation.
- The IdP's `/idp/.well-known` endpoint presents a JSON envelope that contains everything the client needs to know for dynamic discovery.
- The client makes a request to `/idp/profile/oidc/authorize` endpoint which is first handled by Spring Security OAuth. 
- Since the request requires an existing authentication to succeed, Spring Security OAuth throws a `InsufficientAuthenticationException`.
- The IdP is configured to ignore the this exception so that downstream Spring Security components/filters can process it later. This is done via `mvc-beans.xml`. 
- `ExceptionTranslationFilter` of Spring Security kicks in, and attempts to handle the request. The request is then routed to Spring Security for authentication.
- The Idp has configured Spring Security for form-based authentication, which allows the request to be routed to a `login` endpoint for authentication.
- The `login` endpoints invokes Spring Webflow to recall the OIDC login flow to start the flow.
- The `login` flow eventually reaches the authentication state allowing for end-user login.
- Once the authentication is successful, the result is then `POST`ed back to Spring Security to resume the `/idp/profile/oidc/authorize` endpoint functionality.
- The `/idp/profile/oidc/authorize` will proceed to issue a `code` for the given request does a `POST` back to the client.
- The client asks the `/idp/profile/oidc/token` endpoint for an access token, via the `code` received.
- Spring Security OAuth, having recognized an existing authentication session issues an access token back along with an `idToken` in a JWT format. 
- The client validates the access token and the idToken, optionally invoking the `/idp/profile/oidc/jwk` endpoint to verify the `idToken`.
- The client will use the access token to issue a request to `/idp/profile/oidc/userinfo` to grab claims. 

There are many many other permutations of this flow, and many additional extension parameters that could be passed. To learn about all that is possible in this flow, Study [the basics of the specification](http://openid.net/specs/openid-connect-basic-1_0.html).

#### Authentication Context/Method Ref
This extension supports the `acr/amr` claims. If the client requests a specific `acr_value` in the original request, the IdP attempts to calculate whether that value is indeed supported by any of the authentication flows. If none is deemed viable, the authentication context weight map of the IdP is consulted to figure out the appropriate `acr`. The result is passed onto the IdP for authentication. 

Since MITREid Connect at this point does not natively support `acr/amr` claims, an implementation of a claim service is provided by this extension to handle `acr/amr` claims for the client. 

#### Max-Age, AuthN Time
This extension supports the `max_age` and `auth_time` claims. If `max_age` is provided in the original request, the IdP attempts to calculate the authentication creation instant and may simulate a `forcedAuthN` so the end-user is actively reauthenticated. 

Since MITREid Connect's support for these claims is stricyly tied to an authentication that is very much handled by Spring Security, a custom service is provided by this extension to handle the production of `max_age` and `auth_time`. 

## Default IdP Configuration 
Follow the below steps if you wish to enable this extension inside a vanilla IdP v3 deployment. Note that synchronization of changes, as we make progress here, is entirely manual at this point.

### Build

```bash
git clone git@github.com:uchicago/shibboleth-oidc.git
```

Or download [a zip distribution](https://github.com/uchicago/shibboleth-oidc/archive/master.zip).

Build the codebase via:

```bash
./mvn[w] clean package -P new
```

### Cross Examine Changes

Unzip the `target/idp.war` artifact into an `idp-temp`. This will be used as a reference to copy configuration into your IdP deployment.

- Cross examine the `idp-temp/WEB-INF.xml` with your IdP and apply all differences. 
- Cross examine the `idp-temp/idp/login.vm` and `idp-temp/idp/intercept/attribute-release.vm` with your IdP and apply all differences. 
- Cross examine the `idp-temp/idp/system/conf/global-system.xml` with your IdP and apply all differences. 
- Cross examine the `idp-temp/idp/system/conf/webflow-config.xml` with your IdP and apply all differences. 
- Cross examine the `idp-temp/idp/system/conf/mvc-beans.xml` with your IdP and apply all differences. 
- Cross examine the `idp-temp/idp/conf/idp.properties` with your IdP and apply all differences. 
- Cross examine the `idp-temp/idp/conf/attribute-resolver.xml` with your IdP and apply all differences. 
- Cross examine the `idp-temp/idp/conf/attribute-filter.xml` with your IdP and apply all differences. 
- Cross examine the `idp-temp/idp/conf/relying-party.xml` with your IdP and apply all differences. 

### Copy Configuration

- Copy `idp-temp/idp/conf/oidc.properties`, `idp-temp/idp/conf/oidc-protocol.xml` and `idp-temp/idp/conf/schema.sql` into `$IDP_HOME/conf`
- Copy `idp-temp/idp/credentials/keystore.jwks` into `$IDP_HOME/credentials`
- Copy `idp-temp/idp/system/conf/oidc-protocol-*.xml` into `$IDP_HOME/system/conf`
- Copy `idp-temp/idp/system/flows/oidc` into `$IDP_HOME/system/flows`
- Copy `idp-temp/idp/system/views/oidc` into `$IDP_HOME/system/views`

### Copy JARs
Cross examine the `idp-temp/WEB-INF/lib` directory with your IdP and copy all JARs that are not present. 

### Logging

The following packages may be used for log configuration:

```xml
<logger name="org.mitre" level="WARN" />
<logger name="org.hibernate" level="WARN" />

<logger name="org.springframework.web" level="WARN" />
<logger name="org.springframework.webflow" level="WARN" />
<logger name="org.springframework.security" level="WARN" />
<logger name="org.springframework.security.oauth2" level="WARN" />
<logger name="net.shibboleth.idp.oidc" level="WARN" />
```

## Overlay IdP Configuration
The project itself follows an overlay-module where the IdP is configured to embed all of its configuration inside the final war artifact. In doing so, the following changes are then overlaid into the IdP context and need to be accounted for during IdP upgrades. 

* `login.vm` and `attribute-release.vm` are overlaid to account for CSRF changes
* `password-authn-config.xml` is overlaid to indicate JAAS is used for authN. 
* `global-system.xml` registers the `oidc-protocol-system` file
* `webflow-config.xml` is overlaid to add the OIDC flow configuration.
* `mvc-beans.xml` is used in the overlay `conf` directory to override the default beans and config.
 - This is used to define a new view resolver based on Spring bean names and remaps the excluded exceptions from the view resolver. 
* A custom JAR is dropped into the overlay's `WEB-INF/lib` that mocks authentication. This is configured via the `jaas.config` file.
* `oidc.properties` controls the OIDC module configuration. This is appended to the list of property files loaded by 
the IdP via `idp.properties`. 
* `web.xml` is modified to register the `.well-known` endpoint.

### Build [![Build Status](https://travis-ci.org/uchicago/shibboleth-oidc.svg?branch=master)](https://travis-ci.org/uchicago/shibboleth-oidc)
In order to run the overlay build, examine the `/conf/idp.properties` inside the `idp-webapp-overlay` module,
and adjust the values of hostname, entityId, passwords, etc. Then from the command prompt, execute:

#### Initial installs

```bash
./mvn[w] clean package -P new
```

This will wipe out any previous files inside `credentials` and `metadata` directories and start anew.

#### Subsequent installs

```bash
./mvn[w] clean package
```

### Run

#### Prepare HTTPS

You will also need to set up a keystore under `/etc/jetty` and name it `thekeystore`. The keystore password and the 
key password should both be `changeit`.
 
A sample keystore is provided under the `idp-webapp-overlay/etc/jetty` directory that is empty, and can be used to set up the environment. 

#### Run Jetty
From the root directory, run the following command:

```bash
./mvn[w] clean package verify -Dhost=jetty
```

This will spin up an embedded Jetty server to load the IdP context. Remote debugging is available under port 5000 from your IDE.

If you want a somewhat faster build, run:

```bash
./mvn[w] clean package verify -Dhost=jetty --projects idp-oidc-impl,idp-webapp-overlay
```


