<div style="text-align:right"><img src="https://raw.githubusercontent.com/gematik/gematik.github.io/master/Gematik_Logo_Flag_With_Background.png" width="250" height="47" alt="gematik GmbH Logo"/> <br/> </div> <br/> 

# Certificate Update Service

[![Quality Gate Status](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acertificate-update-service&metric=alert_status&token=13b3e1eb2d7195164379e837c3deb13203dd1d5a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acertificate-update-service)[![Vulnerabilities](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acertificate-update-service&metric=vulnerabilities&token=13b3e1eb2d7195164379e837c3deb13203dd1d5a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acertificate-update-service)[![Bugs](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acertificate-update-service&metric=bugs&token=13b3e1eb2d7195164379e837c3deb13203dd1d5a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acertificate-update-service)[![Code Smells](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acertificate-update-service&metric=code_smells&token=13b3e1eb2d7195164379e837c3deb13203dd1d5a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acertificate-update-service)[![Code Smells](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acertificate-update-service&metric=code_smells&token=13b3e1eb2d7195164379e837c3deb13203dd1d5a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acertificate-update-service)[![Coverage](https://sonar.prod.ccs.gematik.solutions/api/project_badges/measure?project=de.gematik.demis%3Acertificate-update-service&metric=coverage&token=13b3e1eb2d7195164379e837c3deb13203dd1d5a)](https://sonar.prod.ccs.gematik.solutions/dashboard?id=de.gematik.demis%3Acertificate-update-service)

<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#release-notes">Release Notes</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#feature-flags">Feature Flags</a></li>
    <li><a href="#security-policy">Security Policy</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

## About The Project

This Service runs as a standalone CLI application and retrieves and validates the X509 Certificates of Users stored in the DEMIS Keycloak instance.
The Validation runs against the D-Trust Public LDAP Registry, using the OCSP Protocol and the Certificate Revocation List.

The Certificates are stored in a Redis Server, running in the DEMIS Infrastructure.

### Release Notes

See [ReleaseNotes.md](./ReleaseNotes.md) for all information regarding the (newest) releases.

## Getting Started

### Prerequisites

The Project requires Java 21 and Maven 3.8+.

### Installation

The Project can be built with the following command:

```sh
mvn clean install
```

The Docker Image associated to the service can be built with the extra profile `docker`:

```sh
mvn clean install -Pdocker
```

## Usage

The application can be executed from a JAR file or a Docker Image:

```sh
# As JAR Application
java -jar target/certificate-update-service.jar
# As Docker Image
docker run --rm -it -p 8080:8080 certificate-update-service:latest
```

It can also be deployed on Kubernetes by using the Helm Chart defined in the folder `deployment/helm/certificate-update-service`:

```ssh
helm install certificate-update-service ./deployment/helm/certificate-update-service
```

**Important**: It requires a Keycloak and a Redis Account, defined as environment variables, in order to let it fetch the Users' list and update the certificates in Redis.


## Feature Flags
For the Live-Test Environment, and for all the Environments where there is a need to load a set of existing Certificates from the File System, the Feature Flag `feature.flag.import.from.disk` should be set to `true`. As source folder, the path specified with the property `cert.root.folder.path` will be used and the certificates will be uploaded to the Redis Server.

## Security Policy
If you want to see the security policy, please check our [SECURITY.md](.github/SECURITY.md).

## Contributing
If you want to contribute, please check our [CONTRIBUTING.md](.github/CONTRIBUTING.md).

## License
Copyright 2023-2025 gematik GmbH

EUROPEAN UNION PUBLIC LICENCE v. 1.2

EUPL © the European Union 2007, 2016

See the [LICENSE](./LICENSE.md) for the specific language governing permissions and limitations under the License

## Additional Notes and Disclaimer from gematik GmbH

1. Copyright notice: Each published work result is accompanied by an explicit statement of the license conditions for use. These are regularly typical conditions in connection with open source or free software. Programs described/provided/linked here are free software, unless otherwise stated.
2. Permission notice: Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
    1. The copyright notice (Item 1) and the permission notice (Item 2) shall be included in all copies or substantial portions of the Software.
    2. The software is provided "as is" without warranty of any kind, either express or implied, including, but not limited to, the warranties of fitness for a particular purpose, merchantability, and/or non-infringement. The authors or copyright holders shall not be liable in any manner whatsoever for any damages or other claims arising from, out of or in connection with the software or the use or other dealings with the software, whether in an action of contract, tort, or otherwise.
    3. We take open source license compliance very seriously. We are always striving to achieve compliance at all times and to improve our processes. If you find any issues or have any suggestions or comments, or if you see any other ways in which we can improve, please reach out to: ospo@gematik.de
3. Please note: Parts of this code may have been generated using AI-supported technology. Please take this into account, especially when troubleshooting, for security analyses and possible adjustments.

## Contact
E-Mail to [DEMIS Entwicklung](mailto:demis-entwicklung@gematik.de?subject=[GitHub]%20Certificate-Update-Service)