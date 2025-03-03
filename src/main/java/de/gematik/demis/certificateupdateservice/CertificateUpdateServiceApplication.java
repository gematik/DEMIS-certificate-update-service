package de.gematik.demis.certificateupdateservice;

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

import de.gematik.demis.certificateupdateservice.updater.CertificateUpdateService;
import de.gematik.demis.service.base.error.rest.ErrorHandlerConfiguration;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.cloud.openfeign.EnableFeignClients;

@SpringBootApplication(
    exclude = {DataSourceAutoConfiguration.class, ErrorHandlerConfiguration.class})
@EnableFeignClients
@RequiredArgsConstructor
public class CertificateUpdateServiceApplication implements CommandLineRunner {

  private final CertificateUpdateService certificateUpdateService;

  /**
   * Wraps the SpringBoot Application with exit, so it can return a valid exit code.
   *
   * @param args command line arguments
   */
  public static void main(String[] args) {
    SpringApplication.run(CertificateUpdateServiceApplication.class, args);
  }

  @Override
  public void run(final String... args) throws Exception {
    certificateUpdateService.updateData();
  }
}
