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
 * #L%
 */

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class KeycloakConnectionService {

  private final KeycloakClient keyCloakClient;

  private final String username;
  private final String password;
  private final String clientId;
  private final String grantType;

  public KeycloakConnectionService(
      @Value("${keycloak.username}") String username,
      @Value("${keycloak.password}") String password,
      @Value("${keycloak.clientId}") String clientId,
      @Value("${keycloak.grantType}") String grantType,
      KeycloakClient keyCloakClient) {
    this.username = username;
    this.password = password;
    this.clientId = clientId;
    this.grantType = grantType;
    this.keyCloakClient = keyCloakClient;
  }

  public Set<String> fetchUserIds() {
    String token = getToken();
    return getUserIds(token);
  }

  private String getToken() {

    log.info("call for token");
    ResponseEntity<String> token = keyCloakClient.getToken(username, password, clientId, grantType);
    String body = token.getBody();

    log.debug("recieved body: {}", body);
    JSONObject bodyAsJson = new JSONObject(body);

    return bodyAsJson.getString("access_token");
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
