package de.gematik.demis.certificateupdateservice.connector.dtrust.helpers;

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

import static de.gematik.demis.certificateupdateservice.connector.dtrust.CertificateUtils.generateOcspRequest;
import static de.gematik.demis.certificateupdateservice.connector.dtrust.CertificateUtils.getOcspUrl;
import static de.gematik.demis.certificateupdateservice.connector.dtrust.CertificateUtils.getRevocationList;
import static de.gematik.demis.certificateupdateservice.connector.dtrust.CertificateUtils.isOcspResponsePositive;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

@Slf4j
public class OnlineCertificateValidator {
  private final long retryTimeMillis;
  private final OcspConnectionTool ocspConnectionTool;
  private final X509Certificate caSubCert;
  private final Marker fatal = MarkerFactory.getMarker("FATAL");

  public OnlineCertificateValidator(X509Certificate caSubCert)
      throws IOException, URISyntaxException {
    this(
        caSubCert,
        Duration.ofSeconds(60).toMillis(),
        new OcspConnectionTool(getOcspUrl(caSubCert)));
  }

  public OnlineCertificateValidator(X509Certificate caSubCert, long retryTimeMillis)
      throws IOException, URISyntaxException {
    this(caSubCert, retryTimeMillis, new OcspConnectionTool(getOcspUrl(caSubCert)));
  }

  public OnlineCertificateValidator(
      X509Certificate caSubCert, long retryTimeMillis, OcspConnectionTool ocspConnectionTool) {
    this.caSubCert = caSubCert;
    this.retryTimeMillis = retryTimeMillis;
    this.ocspConnectionTool = ocspConnectionTool;
  }

  /**
   * Validates the certificates using OCSP and against a CRL. Removes all certificates that are not
   * valid from the @userCertificates map.
   *
   * @param userCertificates the map of user ids and their certificates
   */
  public void validate(final Map<String, List<X509Certificate>> userCertificates) {
    for (var entry : userCertificates.entrySet()) {
      var userCerts = entry.getValue();
      if (!userCerts.isEmpty()) {
        userCerts.removeIf(
            x509Certificate -> !performOnlineValidation(x509Certificate, entry.getKey()));
      }
    }
  }

  /**
   * Performs the online validation of the certificate using OCSP and CRL. It checks if the
   * certificate is valid and not revoked.
   *
   * @param cert the certificate to validate
   * @param userId the user id of the certificate
   * @return true if the certificate is valid and not revoked, false otherwise
   */
  boolean performOnlineValidation(final X509Certificate cert, final String userId) {
    // Perform the check with a backoff retry mechanism
    int retryCount = 0;
    while (retryCount < 3) {
      try {
        return isValid(cert, userId) && !isRevoked(cert);
      } catch (Exception e) {
        log.error("Validation failed for user {}: {}", userId, e.getLocalizedMessage());
        retryCount++;
        try {
          log.warn(
              "Validation failed for user {}, retrying in {} ms",
              userId,
              retryCount * retryTimeMillis);
          Thread.sleep(retryCount * retryTimeMillis);
        } catch (InterruptedException iex) {
          Thread.currentThread().interrupt();
          log.error("Thread interrupted while waiting for retry {}", retryCount);
        }
      }
    }

    return false;
  }

  /** Checks if the certificate is revoked using the CRL. */
  boolean isRevoked(final X509Certificate cert) {
    try {
      final X509CRL crl = getRevocationList(cert);
      return crl.isRevoked(cert);
    } catch (Exception e) {
      log.error(
          "Error while checking certificate revocation: {}. Assuming that the certificate is revoked",
          e.getMessage());
      return true;
    }
  }

  /** Service that performs the OCSP validation of certificate for a particular user. */
  boolean isValid(final X509Certificate cert, final String userId) throws CertificateException {
    try {
      OCSPReq request = generateOcspRequest(cert, caSubCert);
      Optional<OCSPResp> ocspResp = ocspConnectionTool.sendOcspRequest(request.getEncoded());
      return ocspResp.isPresent() && isOcspResponsePositive(ocspResp.get(), userId);
    } catch (Exception e) {
      log.error(fatal, "OCSP request failed for user {}: {}", userId, e.getLocalizedMessage());
      throw new CertificateException("OCSP request failed for user " + userId);
    }
  }
}
