# Build the library and demo project into a container image

Configurations are defined during the time that the image is built. 
The Dockerfile contains the relevant default configurations to integrate to the [Test Danish Eidas Gateway](https://eidasconnector.test.eid.digst.dk/).

```markdown
ENV DEMO_ENTITY_ID=https://saml.eidsaml-demo-app
ENV DEMO_BASE_URL=http://localhost:8081/eidsaml-demo.java
ENV EID_IDP_URL=https://eidasconnector-dev.test.eid.digst.dk/idp
```

### Build the image with the command
```
docker build -t eid-java-sp -f .\docker\DockerFile --no-cache .
```


### Run the application with the command
```
docker run --rm -it -p 8081:8080 eid-java-sp
```
