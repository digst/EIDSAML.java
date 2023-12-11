The [EIDSAML.Java](https://github.com/digst/eIDASSAML.java) was built from the [OIOSAML.Java](https://github.com/digst/OIOSAML.Java) to enable Danish Service Providers integration with the Danish Eidas Gateway and avoid library conflicts with the OIOSAML.Java Library.

See content and changes of releases in [release notes](RELEASE_NOTES.md).

# Getting started with EIDSAML.Net

This is the codebase that the EIDSAML.Java components are built from.

## Resource links

*   [Code repository](hhttps://github.com/digst/eIDASSAML.java)

## Repository content

*   **demo**: the demo service provider that references the eidsaml library and has default settings to integrate to the [Test Danish Eidas Gateway](https://eidasconnector.test.eid.digst.dk/)
*   **docker**: docker compose for building the library and running the demo service provider
*   **eidsaml**: source code for the EIDSAML.Java library
*   **readme.html**: This file

## Getting started

The source code contains everything you need to get a demonstration environment up and running, federating with your own local Identity Provider, as well as directly against Danish Eidas Gateway.

For a quick setup, follow the on setting up a test service provider via Docker - [Docker ReadMe](docker/README.md).

On the service provider you should now be able to log in using the the [Test Danish Eidas Gateway](https://eidasconnector.test.eid.digst.dk/).
* You must select the Test Country EU in the [Test Danish Eidas Gateway](https://eidasconnector.test.eid.digst.dk/).

