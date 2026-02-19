package de.gematik.demis.certificateupdateservice.connector.keycloak;

/*-
 * #%L
 * certificate-update-service
 * %%
 * Copyright (C) 2025 - 2026 gematik GmbH
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
 * European Commission – subsequent versions of the EUPL (the "Licence").
 * You may not use this work except in compliance with the Licence.
 *
 * You find a copy of the Licence in the "Licence" file or at
 * https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
 * In case of changes by gematik find details in the "Readme" file.
 *
 * See the Licence for the specific language governing permissions and limitations under the Licence.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 * #L%
 */

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.ConfigurationPropertiesBindException;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class KeycloakConnectionConfigPropertiesTest {

  private final ApplicationContextRunner contextRunner =
      new ApplicationContextRunner()
          .withUserConfiguration(ValidationConfigPropertiesTestConfiguration.class);

  @Test
  void validProperties() {
    final String[] validProperties = {
      "keycloak.username=admin",
      "keycloak.password=geheim123",
      "keycloak.clientSecret=123456",
      "keycloak.clientId=cus-cli",
      "keycloak.grantType=password"
    };
    contextRunner
        .withPropertyValues(validProperties)
        .run(
            context -> {
              assertThat(context).hasNotFailed();
              final var properties = context.getBean(KeycloakConnectionConfigProperties.class);

              assertThat(properties).isNotNull();
              assertThat(properties.username()).isEqualTo("admin");
              assertThat(properties.password()).isEqualTo("geheim123");
              assertThat(properties.clientSecret()).isEqualTo("123456");
              assertThat(properties.clientId()).isEqualTo("cus-cli");
              assertThat(properties.grantType()).isEqualTo("password");
            });
  }

  @Test
  void missingClientSecretWithGrantTypeClientCredentialsThrowsException() {
    final String[] props = {"keycloak.clientId=cus-cli", "keycloak.grantType=client_credentials"};
    contextRunner
        .withPropertyValues(props)
        .withPropertyValues()
        .run(
            context -> {
              assertThat(context)
                  .hasFailed()
                  .getFailure()
                  .isInstanceOf(ConfigurationPropertiesBindException.class);
            });
  }

  @Test
  void missingPasswordWithGrantTypePasswordThrowsException() {
    final String[] props = {
      "keycloak.username=admin", "keycloak.clientId=cus-cli", "keycloak.grantType=password"
    };
    contextRunner
        .withPropertyValues(props)
        .withPropertyValues()
        .run(
            context -> {
              assertThat(context)
                  .hasFailed()
                  .getFailure()
                  .isInstanceOf(ConfigurationPropertiesBindException.class);
            });
  }

  @TestConfiguration
  @EnableConfigurationProperties(KeycloakConnectionConfigProperties.class)
  static class ValidationConfigPropertiesTestConfiguration {}
}
