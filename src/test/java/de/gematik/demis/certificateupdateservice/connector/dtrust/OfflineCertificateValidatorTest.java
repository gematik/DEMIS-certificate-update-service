package de.gematik.demis.certificateupdateservice.connector.dtrust;

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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

import de.gematik.demis.certificateupdateservice.BaseFileLoaderTestHelper;
import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.OfflineCertificateValidator;
import java.io.FileNotFoundException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.TestConfiguration;

@TestConfiguration
class OfflineCertificateValidatorTest extends BaseFileLoaderTestHelper {

  @Test
  void shouldGiveEmptyListOnExpiredCertificates()
      throws FileNotFoundException, CertificateException {

    X509Certificate userCert =
        getX509CertificateFromFileName("certificates/self-signed/GA-1.01.0.53._.crt");
    X509Certificate userCertNoValid =
        getX509CertificateFromFileName("certificates/self-signed/GA-1.01.0.53._notValid.crt");
    X509Certificate userCertExpired = mock(X509Certificate.class);
    doThrow(new CertificateExpiredException()).when(userCertExpired).checkValidity(any(Date.class));
    X509Certificate userCertNotYetValid = mock(X509Certificate.class);
    doThrow(new CertificateNotYetValidException())
        .when(userCertNotYetValid)
        .checkValidity(any(Date.class));
    X509Certificate userCertEncodingException = mock(X509Certificate.class);
    doThrow(new CertificateEncodingException()).when(userCertEncodingException).getEncoded();

    OfflineCertificateValidator offlineCertificateValidator =
        new OfflineCertificateValidator(caCert, subCa);

    Map<String, List<X509Certificate>> map = new HashMap<>();
    map.put("GA-1.01.0.53.", new ArrayList<>(List.of(userCert)));
    map.put("GA-1.01.0.53._notValid", new ArrayList<>(List.of(userCertNoValid)));
    map.put("userCertExpired", new ArrayList<>(List.of(userCertExpired)));
    map.put("userCertNotYetValid", new ArrayList<>(List.of(userCertNotYetValid)));
    map.put("userCertEncodingException", new ArrayList<>(List.of(userCertEncodingException)));

    offlineCertificateValidator.offlineValidation(map);

    map.forEach((s, x509Certificates) -> assertThat(x509Certificates).isEmpty());
  }

  @Test
  void shouldRemoveExpiredCertificatesFromList()
      throws FileNotFoundException, CertificateException {

    final X509Certificate userCert =
        getX509CertificateFromFileName("certificates/self-signed/GA-1.01.0.53._.crt");
    X509Certificate userCertExpired = mock(X509Certificate.class);
    doThrow(new CertificateExpiredException()).when(userCertExpired).checkValidity(any(Date.class));
    X509Certificate userCertNotYetValid = mock(X509Certificate.class);
    doThrow(new CertificateNotYetValidException())
        .when(userCertNotYetValid)
        .checkValidity(any(Date.class));
    X509Certificate userCertEncodingException = mock(X509Certificate.class);
    doThrow(new CertificateEncodingException()).when(userCertEncodingException).getEncoded();

    final OfflineCertificateValidator offlineCertificateValidator =
        new OfflineCertificateValidator(caCert, subCa);

    final Map<String, List<X509Certificate>> map = new HashMap<>();
    map.put(
        "GA-1.01.0.53.",
        new ArrayList<>(
            List.of(userCert, userCertExpired, userCertNotYetValid, userCertEncodingException)));

    offlineCertificateValidator.offlineValidation(map);

    assertThat(map.get("GA-1.01.0.53.")).isEmpty();
  }
}
