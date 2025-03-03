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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

@ExtendWith(MockitoExtension.class)
class KeycloakConnectionServiceTest {

  private KeycloakConnectionService keycloakConnectionService;

  @Mock private KeycloakClient keycloakClient;

  @Test
  void shouldCallKeycloakClientAndReturnUserIdList() {

    keycloakConnectionService =
        new KeycloakConnectionService(
            "username", "password", "clientId", "grantType", keycloakClient);

    Map<String, String> map = new HashMap<>();
    map.put("access_token", "someTokenString");
    JSONObject jsonbody = new JSONObject(map);
    when(keycloakClient.getToken("username", "password", "clientId", "grantType"))
        .thenReturn(ResponseEntity.ok(jsonbody.toString()));

    when(keycloakClient.getUsers("Bearer someTokenString", Integer.MAX_VALUE))
        .thenReturn(ResponseEntity.ok(List.of(new KeycloakProperties("1."))));

    Set<String> strings = keycloakConnectionService.fetchUserIds();

    assertThat(strings).containsExactly("1.");
  }

  @Test
  void shouldReturnEmptyUserListForMissingBody() {

    keycloakConnectionService =
        new KeycloakConnectionService(
            "username", "password", "clientId", "grantType", keycloakClient);

    Map<String, String> map = new HashMap<>();
    map.put("access_token", "someTokenString");
    JSONObject jsonbody = new JSONObject(map);
    when(keycloakClient.getToken("username", "password", "clientId", "grantType"))
        .thenReturn(ResponseEntity.ok(jsonbody.toString()));

    when(keycloakClient.getUsers("Bearer someTokenString", Integer.MAX_VALUE))
        .thenReturn(ResponseEntity.ok().build());

    Set<String> strings = keycloakConnectionService.fetchUserIds();

    assertThat(strings).isEmpty();
  }
}
