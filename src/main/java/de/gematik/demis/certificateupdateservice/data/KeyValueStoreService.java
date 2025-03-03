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

import de.gematik.demis.certificateupdateservice.error.CusErrorTypeEnum;
import de.gematik.demis.certificateupdateservice.error.CusExecutionException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class KeyValueStoreService {

  private final CertificateRepository certificateRepository;

  public KeyValueStoreService(CertificateRepository certificateRepository) {
    this.certificateRepository = certificateRepository;
  }

  /**
   * Retrieves all certificates from the key value store.
   *
   * @return all certificates from the key value store
   */
  public Iterable<CertificateDataEntity> findAllCertificates() {
    log.info("Retrieving all the stored information from the key value store");
    return certificateRepository.findAll();
  }

  public Set<String> findAllUserEntries() {
    log.info("Retrieving all user IDs from the key value store");
    final var entries = findAllCertificates();
    return StreamSupport.stream(entries.spliterator(), false)
        .map(CertificateDataEntity::id)
        .collect(Collectors.toSet());
  }

  /**
   * Removes entries from the key value store that do not have a valid certificate.
   *
   * @param certificates the certificates to store
   * @param allKeycloakUsers the set of all user IDs in Keycloak to check against
   */
  public void deleteInvalidEntries(
      final Map<String, X509Certificate> certificates, final Set<String> allKeycloakUsers) {
    final var entriesToBeRemoved =
        certificates.keySet().stream()
            .filter(id -> !allKeycloakUsers.contains(id))
            .collect(Collectors.toUnmodifiableSet());

    log.info(
        "Removing {} entries from key value store that do not have a valid certificate",
        entriesToBeRemoved.size());
    removeEntriesById(entriesToBeRemoved);
  }

  /**
   * Stores the given certificates in the key value store.
   *
   * @param idToCertificateMap map of user id to certificate
   * @return the stored certificates as entities of type {@link CertificateDataEntity}
   */
  public Iterable<CertificateDataEntity> storeCertificates(
      final Map<String, X509Certificate> idToCertificateMap) {
    log.info("Storing {} certificates in repository", idToCertificateMap.size());

    /// Convert Map data to a set of Entities
    final Set<CertificateDataEntity> dataEntities = new HashSet<>(idToCertificateMap.size());
    for (var entry : idToCertificateMap.entrySet()) {
      try {
        dataEntities.add(
            new CertificateDataEntity(
                entry.getKey(), entry.getValue().getEncoded(), LocalDateTime.now()));
      } catch (CertificateEncodingException e) {
        throw new CusExecutionException(
            CusErrorTypeEnum.CERTIFICATE_ENCODING,
            "error encoding certificate for user " + entry.getKey(),
            e);
      }
    }

    try {
      certificateRepository.saveAll(dataEntities);
    } catch (final RuntimeException e) {
      throw new CusExecutionException(
          CusErrorTypeEnum.REDIS, "error saving " + dataEntities.size() + " certificates", e);
    }

    log.info("{} certificates saved to repository", dataEntities.size());
    return dataEntities;
  }

  /**
   * Removes entries from the key value store by their IDs.
   *
   * @param idsToBeRemoved the IDs of the entries to be removed
   */
  public void removeEntriesById(Collection<String> idsToBeRemoved) {
    try {
      certificateRepository.deleteAllById(idsToBeRemoved);
    } catch (final RuntimeException e) {
      throw new CusExecutionException(
          CusErrorTypeEnum.REDIS, "error deleting " + idsToBeRemoved.size() + " omitted users", e);
    }
  }
}
