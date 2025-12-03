package de.gematik.demis.certificateupdateservice.connector.keycloak;

/*-
 * #%L
 * certificate-update-service
 * %%
 * Copyright (C) 2025 gematik GmbH
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

import static org.springframework.util.StringUtils.hasText;

import jakarta.validation.constraints.NotEmpty;
import lombok.Builder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@ConfigurationProperties(prefix = "keycloak")
@Validated
@Builder
@Slf4j
public record KeycloakConnectionConfigProperties(
    String username,
    String password,
    String clientSecret,
    @NotEmpty String clientId,
    @NotEmpty String grantType) {
  public static final String GRANT_TYPE_PASSWORD = "password";
  public static final String GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials";

  public KeycloakConnectionConfigProperties {
    log.info(
        "Keycloak connection properties: username={}, clientId={}, grantType={}",
        username,
        clientId,
        grantType);

    if (GRANT_TYPE_PASSWORD.equalsIgnoreCase(grantType)
        && (!hasText(password) || !hasText(username))) {
      throw new IllegalArgumentException(
          "When grant_type is 'password', username / password must not be empty");
    }

    if (GRANT_TYPE_CLIENT_CREDENTIALS.equalsIgnoreCase(grantType) && !hasText(clientSecret)) {
      throw new IllegalArgumentException(
          "When grant_type is 'client_credentials', clientSecret must not be empty");
    }
  }

  public boolean isClientCredentialsGrantType() {
    return GRANT_TYPE_CLIENT_CREDENTIALS.equalsIgnoreCase(grantType);
  }
}
