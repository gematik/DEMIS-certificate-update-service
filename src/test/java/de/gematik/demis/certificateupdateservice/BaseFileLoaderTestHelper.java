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
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 * #L%
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;

@Slf4j
public abstract class BaseFileLoaderTestHelper {

  public ClassLoader classLoader;
  public X509Certificate subCa;
  public X509Certificate caCert;

  @BeforeEach
  void setUpBase() throws FileNotFoundException, CertificateException {
    classLoader = getClass().getClassLoader();

    subCa = getX509CertificateFromFileName("D-TRUST_Limited_Basic_Test_CA_1-2_2019.crt");

    caCert = getX509CertificateFromFileName("D-TRUST_Limited_Basic_Root_Test_CA_1_2019.crt");
  }

  public X509Certificate getX509CertificateFromFileName(String path) throws CertificateException {
    File file = new File(Objects.requireNonNull(classLoader.getResource(path)).getFile());
    try (InputStream caInputStream = new FileInputStream(file)) {
      return (X509Certificate)
          CertificateFactory.getInstance("X.509").generateCertificate(caInputStream);
    } catch (IOException e) {
      log.error("Failed to load certificate from file: {}", path, e);
      return null;
    }
  }
}
