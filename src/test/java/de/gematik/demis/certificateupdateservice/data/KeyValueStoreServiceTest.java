package de.gematik.demis.certificateupdateservice.data;

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
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.*;

import de.gematik.demis.certificateupdateservice.BaseFileLoaderTestHelper;
import de.gematik.demis.certificateupdateservice.error.CusErrorTypeEnum;
import de.gematik.demis.certificateupdateservice.error.CusExecutionException;
import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class KeyValueStoreServiceTest extends BaseFileLoaderTestHelper {

  @Mock private CertificateRepository certificateRepositoryMock;
  @InjectMocks private KeyValueStoreService keyValueStoreService;

  @BeforeEach
  void setUp() {
    Mockito.reset(certificateRepositoryMock);
  }

  @Test
  void shouldCallDeleteAllForAllIdsNoInGivenList() {
    keyValueStoreService.removeEntriesById(Set.of("3", "4"));
    verify(certificateRepositoryMock).deleteAllById(Set.of("3", "4"));
  }

  @Test
  void shouldSaveGivenListAndReturnLoadedListFormKeyValueStore()
      throws CertificateException, FileNotFoundException {

    Map<String, X509Certificate> map = new HashMap<>();
    X509Certificate cert1 =
        getX509CertificateFromFileName("certificates/self-signed/GA-1.01.0.53._.crt");
    map.put("1", cert1);
    X509Certificate cert2 = getX509CertificateFromFileName("certificates/self-signed/RKI-1._.crt");
    map.put("2", cert2);

    Iterable<CertificateDataEntity> t = Set.of(new CertificateDataEntity("1", null, null));
    when(certificateRepositoryMock.saveAll(anySet())).thenReturn(t);

    Iterable<CertificateDataEntity> certificateDataEntities =
        keyValueStoreService.storeCertificates(map);

    assertThat(certificateDataEntities).isNotEmpty();

    ArgumentCaptor<Set<CertificateDataEntity>> argument = ArgumentCaptor.forClass(Set.class);
    verify(certificateRepositoryMock).saveAll(argument.capture());
    assertThat(argument.getValue()).hasSize(2);
    assertThat(argument.getValue().stream().map(CertificateDataEntity::id)).contains("1", "2");
    assertThat(argument.getValue().stream().map(CertificateDataEntity::encodedCertificate))
        .contains(cert1.getEncoded(), cert2.getEncoded());
  }

  @Test
  void deleteIdsNotInKeycloakThrowsException() {
    doThrow(new RuntimeException("Test")).when(certificateRepositoryMock).deleteAllById(anySet());
    final Set<String> param = Set.of();
    assertThatExceptionOfType(CusExecutionException.class)
        .isThrownBy(() -> keyValueStoreService.removeEntriesById(param))
        .hasFieldOrPropertyWithValue("reason", CusErrorTypeEnum.REDIS)
        .havingCause();
  }

  @Test
  void saveAllCertificatesThrowsException() {
    doThrow(new RuntimeException("Test")).when(certificateRepositoryMock).saveAll(anySet());
    final Map<String, X509Certificate> param = Map.of();
    assertThatExceptionOfType(CusExecutionException.class)
        .isThrownBy(() -> keyValueStoreService.storeCertificates(param))
        .hasFieldOrPropertyWithValue("reason", CusErrorTypeEnum.REDIS)
        .havingCause();
  }
}
