package de.gematik.demis.certificateupdateservice.connector.dtrust;

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

import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.CertificateDownloaderService;
import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.OfflineCertificateValidator;
import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.OnlineCertificateValidator;
import java.security.cert.X509Certificate;
import java.util.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Service to retrieve valid certificates from LDAP Server and validate them against OCSP and
 * offline with CA.
 */
@Service
@Slf4j
public class LdapService {

  private final CertificateDownloaderService certificateDownloaderService;
  private final OfflineCertificateValidator offlineCertificateValidator;
  private final OnlineCertificateValidator ocspCertificateValidator;

  /**
   * Constructor for LdapService.
   *
   * @param certificateDownloaderService the certificate downloader service
   * @param offlineCertificateValidator the offline certificate validator
   * @param ocspCertificateValidator the ocsp certificate validator
   */
  public LdapService(
      CertificateDownloaderService certificateDownloaderService,
      OfflineCertificateValidator offlineCertificateValidator,
      OnlineCertificateValidator ocspCertificateValidator) {

    this.certificateDownloaderService = certificateDownloaderService;

    this.offlineCertificateValidator = offlineCertificateValidator;
    this.ocspCertificateValidator = ocspCertificateValidator;
  }

  /**
   * Retrieve valid certificates from LDAP Server and validates them against OCSP and offline with
   * CA.
   *
   * @param userIds the user ids to retrieve the certificates for
   * @return a map of user ids and their last valid certificate
   */
  public Map<String, X509Certificate> retrieveValidCertificates(Set<String> userIds) {
    log.info("starting download of certificates from LDAP Server");
    final Map<String, List<X509Certificate>> userCertificates =
        certificateDownloaderService.downloadCertificates(userIds);

    log.info("certificate download finished, starting offlineValidation");
    offlineCertificateValidator.offlineValidation(userCertificates);

    log.info("offlineValidation finished, starting ocspValidation");
    ocspCertificateValidator.validate(userCertificates);

    log.info("ocspValidation finished, extracting latest valid certificates");
    return getLatestValidCertificates(userCertificates);
  }

  private HashMap<String, X509Certificate> getLatestValidCertificates(
      final Map<String, List<X509Certificate>> userCertificates) {
    HashMap<String, X509Certificate> validCertificates = new HashMap<>(userCertificates.size());
    for (var entry : userCertificates.entrySet()) {
      final List<X509Certificate> certList = entry.getValue();
      if (certList.size() == 1) {
        validCertificates.put(entry.getKey(), entry.getValue().getFirst());
      } else if (!certList.isEmpty()) {
        X509Certificate newestCert =
            Collections.max(certList, Comparator.comparing(X509Certificate::getNotBefore));
        validCertificates.put(entry.getKey(), newestCert);
      }
    }
    return validCertificates;
  }
}
