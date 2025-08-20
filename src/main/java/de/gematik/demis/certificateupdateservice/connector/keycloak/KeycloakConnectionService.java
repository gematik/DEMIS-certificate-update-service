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

import static org.springframework.util.StringUtils.hasText;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Slf4j
@RequiredArgsConstructor
@Service
public class KeycloakConnectionService {

  private final KeycloakConnectionConfigProperties props;
  private final KeycloakClient keyCloakClient;

  public Set<String> fetchUserIds() {
    String token = getToken();
    return getUserIds(token);
  }

  String getToken() {
    final String jsonResponse = callGetToken();

    final JSONObject bodyAsJson = new JSONObject(jsonResponse);

    return bodyAsJson.getString("access_token");
  }

  private String callGetToken() {
    if (props.isClientCredentialsGrantType()) {
      log.info("call for token with service account client secret");
      return keyCloakClient.getTokenWithClientSecretForServiceAccount(
          props.clientId(), props.grantType(), props.clientSecret());
    } else {
      if (hasText(props.clientSecret())) {
        log.info("call for token with username and password and client secret");
        return keyCloakClient.getTokenWithPasswordAndClientSecret(
            props.username(),
            props.password(),
            props.clientId(),
            props.grantType(),
            props.clientSecret());

      } else {
        log.info("call for token with username and password");
        return keyCloakClient.getTokenWithPassword(
            props.username(), props.password(), props.clientId(), props.grantType());
      }
    }
  }

  private Set<String> getUserIds(String token) {
    log.info("Fetching users from keycloak");
    ResponseEntity<List<KeycloakProperties>> users =
        keyCloakClient.getUsers("Bearer " + token, Integer.MAX_VALUE);
    var body = users.getBody();
    if (body != null && !body.isEmpty()) {
      Set<String> userIds =
          body.stream().map(KeycloakProperties::username).collect(Collectors.toSet());
      log.info("received {} user ids", userIds.size());
      return userIds;
    }
    log.info("Returning empty set of user ids from keycloak");
    return Collections.emptySet();
  }
}
