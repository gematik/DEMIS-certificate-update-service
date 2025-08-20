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
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.matching.StringValuePattern;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.autoconfigure.http.HttpMessageConvertersAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.cloud.openfeign.EnableFeignClients;
import org.springframework.cloud.openfeign.FeignAutoConfiguration;
import org.springframework.http.MediaType;

@AutoConfigureWireMock(port = 0)
@ImportAutoConfiguration({
  FeignAutoConfiguration.class,
  HttpMessageConvertersAutoConfiguration.class
})
@EnableFeignClients(clients = KeycloakClient.class)
@SpringBootTest(
    classes = {KeycloakClient.class},
    properties = {
      "demis.network.keycloak-base-address=http://localhost:${wiremock.server.port}",
      "demis.network.keycloak-token-address=/realms/myrealm/protocol/openid-connect/token"
    })
class KeycloakConnectionServiceIntegrationTest {

  private static final String TOKEN_URL = "/realms/myrealm/protocol/openid-connect/token";
  private static final String EXPECTED_TOKEN = "myTestToken";

  @Autowired private KeycloakClient client;

  private static void verifyRequestBody(final List<String> expectedForm) {
    verify(
        postRequestedFor(urlEqualTo(TOKEN_URL))
            .withRequestBody(formToContentPattern(expectedForm)));
  }

  private static StringValuePattern formToContentPattern(final List<String> formParams) {
    return formParams.stream()
        .map(WireMock::containing)
        .reduce(StringValuePattern::and)
        .orElse(containing(""));
  }

  @BeforeEach
  void setupWiremock() {
    reset();
    stubFor(
        post(urlEqualTo(TOKEN_URL))
            .withHeader("Content-Type", containing(APPLICATION_FORM_URLENCODED_VALUE))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .withBody(
                        "{\"access_token\":\""
                            + EXPECTED_TOKEN
                            + "\",\"expires_in\":300,\"refresh_token\":\"test-refresh\"}")));
  }

  @Test
  void tokenWithPassword() {
    final var props =
        KeycloakConnectionConfigProperties.builder()
            .username("admin")
            .password("geheim")
            .grantType("password")
            .build();
    final List<String> expectedForm =
        List.of("username=admin", "password=geheim", "grant_type=password");

    executeTest(props, expectedForm);
  }

  @Test
  void tokenWithPasswordAndClientSecret() {
    final var props =
        KeycloakConnectionConfigProperties.builder()
            .username("admin")
            .password("geheim")
            .grantType("password")
            .clientSecret("abcd1234")
            .build();
    final List<String> expectedForm =
        List.of(
            "username=admin", "password=geheim", "grant_type=password", "client_secret=abcd1234");

    executeTest(props, expectedForm);
  }

  @Test
  void tokenWithClientSecretForServiceAccount() {
    final var props =
        KeycloakConnectionConfigProperties.builder()
            .grantType("client_credentials")
            .clientSecret("abcd1234")
            .build();
    final List<String> expectedForm =
        List.of("grant_type=client_credentials", "client_secret=abcd1234");

    executeTest(props, expectedForm);
  }

  private void executeTest(
      final KeycloakConnectionConfigProperties props, final List<String> expectedRequestForm) {
    final var underTest = new KeycloakConnectionService(props, client);
    final String actualToken = underTest.getToken();
    assertThat(actualToken).isEqualTo(EXPECTED_TOKEN);
    verifyRequestBody(expectedRequestForm);
  }
}
