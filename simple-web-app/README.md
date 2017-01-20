simple-web-app
==============

Simple web application that demonstrates the use of the OpenID Connect client code and configuration

## Setup

### Configure properties

You will also need to modify the following file: `src/main/webapp/WEB-INF/servlet.properties`

* `server.url=https://your server url` Replace "https://your server url" with your server url

### Run Jetty
From the root directory, run the following command:

```bash
./mvnw clean package jetty:run-forked
```
