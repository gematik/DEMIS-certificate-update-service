package de.gematik.demis.certificateupdateservice.updater;

/*-
 * #%L
 * certificate-update-service
 * %%
 * Copyright (C) 2025 - 2026 gematik GmbH
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

import static de.gematik.demis.certificateupdateservice.connector.dtrust.CertificateUtils.loadCertificate;

import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.OfflineCertificateValidator;
import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.OnlineCertificateValidator;
import de.gematik.demis.certificateupdateservice.error.CusExecutionException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import lombok.extern.slf4j.Slf4j;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ExitCodeExceptionMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@Slf4j
public class CertificateUpdateConfiguration {

  @Bean
  public LdapNetworkConnection ldapNetworkConnection(
      @Value("${cert.base.url}") String certificateDownloadBaseUrl,
      @Value("${cert.base.port}") int certificateDownloadBasePort) {
    return new LdapNetworkConnection(certificateDownloadBaseUrl, certificateDownloadBasePort);
  }

  @Bean
  public OfflineCertificateValidator offlineCertificateValidator(
      X509Certificate caCert, X509Certificate subCaCert) {
    return new OfflineCertificateValidator(caCert, subCaCert);
  }

  @Bean
  public OnlineCertificateValidator ocspCertificateValidator(X509Certificate subCaCert)
      throws IOException, URISyntaxException {
    return new OnlineCertificateValidator(subCaCert);
  }

  @Bean
  public X509Certificate subCaCert(@Value("${cert.sub.ca.file.path}") String subCaFilePath) {
    return loadCertificate(subCaFilePath);
  }

  @Bean
  public X509Certificate caCert(@Value("${cert.ca.file.path}") String caFilePath) {
    return loadCertificate(caFilePath);
  }

  /**
   * Maps Exceptions to remote codes.
   *
   * @return an instance of {@link ExitCodeExceptionMapper}
   */
  @Bean
  ExitCodeExceptionMapper exitCodeToExceptionMapper() {
    return exception -> {
      if (exception instanceof CusExecutionException cusExecutionException) {
        log.error("Stopping the application with an fatal execution error", exception);
        return cusExecutionException.getReason().ordinal() + 2;
      } else {
        log.error("Stopping the application with an unexpected error", exception);
        return 1;
      }
    };
  }
}
