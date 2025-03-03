package de.gematik.demis.certificateupdateservice.data;

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

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Service;

/** Service that internally handles the operations with the Key-Value Store and the filesystem. */
@Service
public class StorageService {
  private final KeyValueStoreService keyValueStoreService;
  private final CertificateVolumeStorageService certificateVolumeStorageService;

  public StorageService(
      KeyValueStoreService keyValueStoreService,
      CertificateVolumeStorageService certificateVolumeStorageService) {
    this.keyValueStoreService = keyValueStoreService;
    this.certificateVolumeStorageService = certificateVolumeStorageService;
  }

  /**
   * Retrieves all certificates from the FileSystem.
   *
   * @return all certificates from the FileSystem
   */
  public Map<String, X509Certificate> importCertificates() {
    return certificateVolumeStorageService.loadCertificatesFromVolume();
  }

  /**
   * Retrieves all Users from the key value store.
   *
   * @return all certificates from the key value store
   */
  public Set<String> findAllUserEntries() {
    return keyValueStoreService.findAllUserEntries();
  }

  /**
   * Removes entries from the key value store that do not have a valid certificate.
   *
   * @param userIds the users to be removed
   */
  public void removeUnusedIds(final Collection<String> userIds) {
    keyValueStoreService.removeEntriesById(userIds);
  }

  /**
   * Stores the given certificates in the key value store and the filesystem. It removes entries
   * from the key value store that do not have a valid certificate.
   *
   * @param certificates the certificates to store
   * @param allKeycloakUsers the set of all user IDs in Keycloak to check against
   */
  public void storeCertificates(
      final Map<String, X509Certificate> certificates, Set<String> allKeycloakUsers) {

    keyValueStoreService.storeCertificates(certificates);
    keyValueStoreService.deleteInvalidEntries(certificates, allKeycloakUsers);
  }
}
