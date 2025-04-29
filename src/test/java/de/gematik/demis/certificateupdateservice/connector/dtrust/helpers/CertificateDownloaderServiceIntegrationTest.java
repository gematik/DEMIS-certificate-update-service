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
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import de.gematik.demis.certificateupdateservice.error.CusErrorTypeEnum;
import de.gematik.demis.certificateupdateservice.error.CusExecutionException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.junit.jupiter.api.Test;

class CertificateDownloaderServiceIntegrationTest {

  @Test
  void shouldDownloadCertificates() {
    LdapNetworkConnection connection = new LdapNetworkConnection("directory.d-trust.net", 389);
    CertificateDownloaderService certificateDownloaderService =
        new CertificateDownloaderService(connection, List.of("1."));

    Map<String, List<X509Certificate>> stringListMap =
        certificateDownloaderService.downloadCertificates(Set.of("1.", "1.01.0.53.", "3."));

    assertThat(stringListMap).isNotEmpty();
    assertThat(stringListMap.get("1.")).isNotEmpty();
    assertThat(stringListMap.get("1.")).hasSizeGreaterThan(1);

    assertThat(stringListMap.get("1.01.0.53.")).isNotEmpty();
    assertThat(stringListMap.get("1.01.0.53.")).hasSizeGreaterThan(1);
  }

  @Test
  void ldapDown() {
    LdapNetworkConnection connection = new LdapNetworkConnection("unknownhost", 389);
    final var certificateDownloaderService =
        new CertificateDownloaderService(connection, List.of("1."));

    final Set<String> param = Set.of("1.", "1.01.0.53.", "3.");
    assertThatExceptionOfType(CusExecutionException.class)
        .isThrownBy(() -> certificateDownloaderService.downloadCertificates(param))
        .hasFieldOrPropertyWithValue("reason", CusErrorTypeEnum.DTRUST_LDAP)
        .withCauseInstanceOf(LdapException.class);
  }
}
