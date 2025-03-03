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
 * #L%
 */

import static de.gematik.demis.certificateupdateservice.connector.dtrust.CertificateUtils.generateOcspRequest;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.demis.certificateupdateservice.BaseFileLoaderTestHelper;
import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.OcspConnectionTool;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import lombok.SneakyThrows;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OcspConnectionToolIntegrationTest extends BaseFileLoaderTestHelper {

  private OcspConnectionTool ocspConnectionTool;

  @SneakyThrows
  @BeforeEach
  void setUp() throws MalformedURLException {
    URL url = new URI("http://staging.ocsp.d-trust.net").toURL();
    ocspConnectionTool = new OcspConnectionTool(url);
  }

  @Test
  void shouldSendCertificateAndReturnValueFromOCSP()
      throws IOException, CertificateException, OCSPReqException {

    X509Certificate x509Certificate =
        getX509CertificateFromFileName("certificates/self-signed/GA-1.01.0.53._.crt");
    X509Certificate x509Certificate2 =
        getX509CertificateFromFileName("D-TRUST_Limited_Basic_Test_CA_1-2_2019.crt");

    OCSPReq ocspReq = generateOcspRequest(x509Certificate, x509Certificate2);

    Optional<OCSPResp> ocspResp = ocspConnectionTool.sendOcspRequest(ocspReq.getEncoded());

    assertThat(ocspResp.get().getStatus()).isZero();
  }
}
