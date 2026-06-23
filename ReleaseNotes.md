<div style="text-align:right"><img src="https://raw.githubusercontent.com/gematik/gematik.github.io/master/Gematik_Logo_Flag_With_Background.png" width="250" height="47" alt="gematik GmbH Logo"/> <br/> </div> <br/>

# Release Notes
## Release 1.10.0
- upgraded to spring boot 4
- added prometheus pod annotations to helm chart
- arranged jvm options and resource limits
- optimized custom environment variables handling in helm chart
- updated docker base image to gematik1/osadl-alpine-openjdk25-jre:1.0.5

## Release 1.9.1
- updated keycloak to 26.0.9
- updated resteasy to 6.2.16.Final
- updated spring parent to 2.16.0
- set spring-application explicitly to NONE

## Release 1.9.0 
- updated base-image and updated from java 21 to java 25
- removed istio helm chart
- updated maxRAMPercentage to 65%
- updated netty to 4.2.x

## Release 1.8.6
- updated base image

## Release 1.8.5
- fixed pod annotations in helmchart

## Release 1.8.4
- Updated dependencies

## Release 1.8.3
- Updated dependencies

## Release 1.8.2
- Updated dependencies

## Release 1.8.1
- Updated dependencies

## Release 1.8.0
- fixing issue with wrong cn name for hospital certificates to username mapping
- Updated dependencies

## Release 1.7.1
- handle duplicate entries in the certificate

## Release 1.7.0
- Updated ospo-resources for adding additional notes and disclaimer
- setting new ressources in helm chart
- change base chart to istio hostnames
- updating dependencies
- add feature to read labroatory certificates

## Release 1.6.0
- First official GitHub-Release
