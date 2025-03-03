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

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

import java.util.List;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@FeignClient(name = "keycloak", url = "${demis.network.keycloak-base-address}")
public interface KeycloakClient {

  @PostMapping(
      //      value = "/realms/master/protocol/openid-connect/token",
      value = "${demis.network.keycloak-token-address}",
      consumes = APPLICATION_FORM_URLENCODED_VALUE,
      produces = APPLICATION_JSON_VALUE)
  ResponseEntity<String> getToken(
      @RequestPart("username") String username,
      @RequestPart("password") String password,
      @RequestPart("client_id") String clientId,
      @RequestPart("grant_type") String grantType);

  @GetMapping(value = "${demis.network.keycloak-user-data-address}")
  ResponseEntity<List<KeycloakProperties>> getUsers(
      @RequestHeader("Authorization") String bearerToken, @RequestParam("max") Integer max);
}
