package de.gematik.demis.certificateupdateservice.updater;

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

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.gematik.demis.certificateupdateservice.BaseFileLoaderTestHelper;
import de.gematik.demis.certificateupdateservice.connector.dtrust.LdapService;
import de.gematik.demis.certificateupdateservice.connector.keycloak.KeycloakConnectionService;
import de.gematik.demis.certificateupdateservice.data.CertificateDataEntity;
import de.gematik.demis.certificateupdateservice.data.CertificateVolumeStorageService;
import de.gematik.demis.certificateupdateservice.data.KeyValueStoreService;
import de.gematik.demis.certificateupdateservice.data.StorageService;
import java.io.IOException;
import java.nio.file.Path;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CertificateUpdateServiceTest extends BaseFileLoaderTestHelper {

  @Mock private KeycloakConnectionService keyCloakConnectionServiceMock;
  @Mock private KeyValueStoreService keyValueStoreServiceMock;
  @Mock private LdapService ldapServiceMock;
  @Mock private CertificateVolumeStorageService certificateVolumeStorageServiceMock;

  @Test
  void shouldCallServicesAndPassReturnValues() throws CertificateException, IOException {

    final var expectedKeycloakUsers = Set.of("1.01.0.53.", "1.");
    when(keyCloakConnectionServiceMock.fetchUserIds()).thenReturn(expectedKeycloakUsers);
    Map<String, X509Certificate> map = new HashMap<>();
    X509Certificate cert1 =
        getX509CertificateFromFileName("certificates/self-signed/GA-1.01.0.53._.crt");
    map.put("1.01.0.53.", cert1);
    X509Certificate cert2 = getX509CertificateFromFileName("certificates/self-signed/RKI-1._.crt");
    map.put("1.", cert2);
    when(ldapServiceMock.retrieveValidCertificates(expectedKeycloakUsers)).thenReturn(map);

    List<CertificateDataEntity> certificateDataEntities =
        List.of(
            new CertificateDataEntity("1.01.0.53.", cert1.getEncoded(), null),
            new CertificateDataEntity("1.", cert2.getEncoded(), null));
    when(keyValueStoreServiceMock.storeCertificates(map)).thenReturn(certificateDataEntities);

    final Path somepath = Path.of("somepath");

    final StorageService storageService =
        new StorageService(keyValueStoreServiceMock, certificateVolumeStorageServiceMock);

    final CertificateUpdateService certificateUpdateService =
        new CertificateUpdateService(
            keyCloakConnectionServiceMock, ldapServiceMock, storageService, false);
    certificateUpdateService.updateData();

    verify(keyValueStoreServiceMock).deleteInvalidEntries(map, expectedKeycloakUsers);
  }
}
