package de.gematik.demis.certificateupdateservice.integrationtest;

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

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.OcspConnectionTool;
import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.OfflineCertificateValidator;
import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.OnlineCertificateValidator;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import lombok.SneakyThrows;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

@TestConfiguration
public class TestConfig {
  @SneakyThrows
  @Primary
  @Bean
  OnlineCertificateValidator wireMockOcspCertificateValidator(
      X509Certificate subCaCert, @Value("${wiremock.server.port}") String wireMockPort) {
    return new OnlineCertificateValidator(
        subCaCert,
        100,
        new OcspConnectionTool(new URI("http://localhost:" + wireMockPort).toURL()));
  }

  @Primary
  @Bean
  OfflineCertificateValidator fixDateOfflineCertificateValidator(
      X509Certificate caCert, X509Certificate subCaCert) {
    final LocalDate nowLocalDate = LocalDate.of(2023, 8, 30);
    final Date date =
        Date.from(nowLocalDate.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant());
    return new OfflineCertificateValidator(caCert, subCaCert, () -> date);
  }

  @Primary
  @Bean
  public LdapNetworkConnection embeddedLdapNetworkConnection(final InMemoryDirectoryServer ldap) {
    return new LdapNetworkConnection("localhost", ldap.getListenPort());
  }
}
