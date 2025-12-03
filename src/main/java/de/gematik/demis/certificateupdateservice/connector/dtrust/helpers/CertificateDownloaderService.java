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

import de.gematik.demis.certificateupdateservice.error.CusErrorTypeEnum;
import de.gematik.demis.certificateupdateservice.error.CusExecutionException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.MessageFormat;
import java.util.*;
import lombok.extern.slf4j.Slf4j;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/** Service implementing the download of certificates from the D-Trust LDAP server. */
@Service
@Slf4j
public class CertificateDownloaderService {

  private static final String CERTIFICATE_ID = "usercertificate;binary";
  private final List<String> rkiIds;
  private final LdapNetworkConnection connection;

  public CertificateDownloaderService(
      LdapNetworkConnection connection, @Value("${rki.ids}") List<String> rkiIds) {
    this.rkiIds = rkiIds;
    this.connection = connection;
  }

  private static boolean matchCertificateSubjectWithSearchFilter(
      final X509Certificate cert, final String expectedCommonName) {
    // name example:
    // ST=Berlin,2.5.4.5=#130c43534d303234343031393539,L=Berlin,CN=GA-1.01.0.53.,OU=DEMIS,O=Robert
    // Koch-Institut,C=DE
    final String name = cert.getSubjectX500Principal().getName();
    final String cn =
        Arrays.stream(name.split(","))
            .map(String::trim)
            .filter(s -> s.startsWith("CN="))
            .findFirst()
            .map(s -> s.substring(3).trim())
            .orElse("");

    final boolean match = cn.equalsIgnoreCase(expectedCommonName);
    if (!match) {
      log.error(
          "ATTENTION: certificate discarded because subject does not match ldap search! Maybe a Man-in-the-Middle-Attack. "
              + "Ldap search for {} but CN of certificate is {}. Cert={}",
          expectedCommonName,
          cn,
          cert);
    }
    return match;
  }

  /**
   * Establishes a connection to the D-Trust LDAP server and downloads the certificates for the
   * given user ids.
   *
   * @param userIds the user ids to download the certificates for
   * @return a map of user ids and their available certificates
   */
  public Map<String, List<X509Certificate>> downloadCertificates(final Set<String> userIds) {
    try {
      try {
        setUpConnection();
      } catch (final Exception e) {
        throw new CusExecutionException(
            CusErrorTypeEnum.DTRUST_LDAP, "Cannot setup ldap connection", e);
      }

      final Map<String, List<X509Certificate>> returnMap = new HashMap<>(userIds.size());

      for (final String userId : userIds) {
        final List<X509Certificate> downloadedCertificates = new ArrayList<>();

        final String userCn = toCommonNameFromUserId(userId);

        try (final EntryCursor cursor =
            connection.search("C=DE", "(cn=" + userCn + ")", SearchScope.SUBTREE, "*")) {
          cursor.forEach(
              certificate ->
                  parseCertificate(certificate)
                      .filter(c -> matchCertificateSubjectWithSearchFilter(c, userCn))
                      .ifPresent(downloadedCertificates::add));
        } catch (LdapException | IOException e) {
          throw new CusExecutionException(
              CusErrorTypeEnum.DTRUST_LDAP, "Error searching certificate for user " + userId, e);
        }

        log.info(
            "{} certificate download ended with {} found possible certificates",
            userId,
            downloadedCertificates.size());
        returnMap.put(userId, downloadedCertificates);
      }

      return returnMap;
    } finally {
      connection.close();
    }
  }

  private void setUpConnection() throws LdapException {
    connection.getConfig().setUseSsl(false);
    connection.bind();
  }

  private Optional<X509Certificate> parseCertificate(Entry c) {
    try {
      byte[] certificateAsByteCode = c.get(CERTIFICATE_ID).getBytes();
      ByteArrayInputStream bais = new ByteArrayInputStream(certificateAsByteCode);
      X509Certificate clientCert =
          (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bais);
      return Optional.of(clientCert);
    } catch (LdapInvalidAttributeValueException | CertificateException e) {
      log.error("Error while parsing {}", c.get(CERTIFICATE_ID));
      return Optional.empty();
    }
  }

  private String toCommonNameFromUserId(String userId) {
    return MessageFormat.format("{0}-{1}", rkiIds.contains(userId) ? "RKI" : "GA", userId);
  }
}
