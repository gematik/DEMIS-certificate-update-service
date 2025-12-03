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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.CertificateDownloaderService;
import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.OfflineCertificateValidator;
import de.gematik.demis.certificateupdateservice.connector.dtrust.helpers.OnlineCertificateValidator;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class LdapServiceTest {

  private LdapService ldapService;

  @Mock private CertificateDownloaderService certificateDownloaderServiceMock;

  @Mock private OfflineCertificateValidator offlineCertificateValidatorMock;

  @Mock private OnlineCertificateValidator ocspCertificateValidatorMock;

  @BeforeEach
  void setUp() {

    ldapService =
        new LdapService(
            certificateDownloaderServiceMock,
            offlineCertificateValidatorMock,
            ocspCertificateValidatorMock);
  }

  @Test
  void shouldCallServicesAndReturnValidatedValues() {
    Set<String> userIds = Set.of("1", "2", "3");

    X509Certificate cert1 = mock(X509Certificate.class);
    X509Certificate cert2a = mock(X509Certificate.class);
    X509Certificate cert2b = mock(X509Certificate.class);

    Map<String, List<X509Certificate>> certMap = new HashMap<>();
    certMap.put("1.", List.of(cert1));
    certMap.put("2.", List.of(cert2a, cert2b));

    when(certificateDownloaderServiceMock.downloadCertificates(userIds)).thenReturn(certMap);
    doNothing().when(offlineCertificateValidatorMock).offlineValidation(certMap);
    doNothing().when(ocspCertificateValidatorMock).validate(certMap);

    Date date1 =
        Date.from(LocalDateTime.now().minusDays(1).atZone(ZoneId.systemDefault()).toInstant());
    Date date2 =
        Date.from(LocalDateTime.now().minusDays(2).atZone(ZoneId.systemDefault()).toInstant());

    when(cert2a.getNotBefore()).thenReturn(date1);
    when(cert2b.getNotBefore()).thenReturn(date2);

    Map<String, X509Certificate> certificateMap = ldapService.retrieveValidCertificates(userIds);

    assertThat(certificateMap).hasSize(2).containsEntry("1.", cert1).containsEntry("2.", cert2a);
  }
}
