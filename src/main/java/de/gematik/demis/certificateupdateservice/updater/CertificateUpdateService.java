package de.gematik.demis.certificateupdateservice.updater;

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

import de.gematik.demis.certificateupdateservice.connector.dtrust.LdapService;
import de.gematik.demis.certificateupdateservice.connector.keycloak.KeycloakConnectionService;
import de.gematik.demis.certificateupdateservice.data.StorageService;
import de.gematik.demis.certificateupdateservice.error.CusErrorTypeEnum;
import de.gematik.demis.certificateupdateservice.error.CusExecutionException;
import java.time.LocalDateTime;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class CertificateUpdateService {

  private final KeycloakConnectionService keyCloakConnectionService;
  private final LdapService ldapService;
  private final StorageService storageService;
  private final boolean importFromDiskMode;

  public CertificateUpdateService(
      KeycloakConnectionService keycloakConnectionService,
      LdapService ldapService,
      StorageService storageService,
      @Value("${feature.flag.import.from.disk}") boolean importFromDiskMode) {
    this.keyCloakConnectionService = keycloakConnectionService;
    this.ldapService = ldapService;
    this.storageService = storageService;
    this.importFromDiskMode = importFromDiskMode;
  }

  /**
   * Main method to update the certificates. It fetches the certificates from the LDAP and validates
   * them. If the importFromDiskMode is enabled, it will import the certificates from the disk.
   */
  public void updateData() {
    log.info("Certificate update started at {}", LocalDateTime.now());

    if (importFromDiskMode) {
      updateFromFileSystem();
    } else {
      updateFromLdap();
    }

    log.info("Certificate update ended at {}", LocalDateTime.now());
  }

  /**
   * Fetches the user IDs from Keycloak, retrieves the certificates from LDAP and validates them.
   */
  private void updateFromLdap() {
    log.info("Fetching Certificates from LDAP, Validating them with OCSP.");
    try (ExecutorService myExecutor = Executors.newVirtualThreadPerTaskExecutor()) {
      var keycloakUsersFuture = myExecutor.submit(keyCloakConnectionService::fetchUserIds);
      var cachedUsersFuture = myExecutor.submit(storageService::findAllUserEntries);

      final var allKeycloakUsers = keycloakUsersFuture.get();
      final var allCachedUsers = cachedUsersFuture.get();

      // Remove elements from the cache that are not in the keycloak
      if (allCachedUsers.removeAll(allKeycloakUsers)) {
        storageService.removeUnusedIds(allCachedUsers);
      }
      // call LDAP-Service and get certificates with call to OCSP-Service
      final var validCertificates = ldapService.retrieveValidCertificates(allKeycloakUsers);

      // save certificates, removed entries from store if certificates are not valid
      storageService.storeCertificates(validCertificates, allKeycloakUsers);

    } catch (ExecutionException | InterruptedException e) {
      throw new CusExecutionException(CusErrorTypeEnum.GENERIC, "Failed to update certificates", e);
    }
  }

  private void updateFromFileSystem() {
    log.info("Import from disk mode is enabled. Skipping LDAP Import and OCSP Validation.");

    // read the certificates from the disk
    final var certificates = storageService.importCertificates();
    // store the certificates in the key value store only
    storageService.storeCertificates(certificates, certificates.keySet());
  }
}
