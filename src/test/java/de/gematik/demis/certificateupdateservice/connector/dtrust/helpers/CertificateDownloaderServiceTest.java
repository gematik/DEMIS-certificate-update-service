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
 * For additional notes and disclaimer from gematik and in case of changes by gematik,
 * find details in the "Readme" file.
 * #L%
 */

import static org.assertj.core.api.Assertions.as;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.gematik.demis.certificateupdateservice.error.CusErrorTypeEnum;
import de.gematik.demis.certificateupdateservice.error.CusExecutionException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.core.io.ClassPathResource;

class CertificateDownloaderServiceTest {

  private static final String GA_1_01_0_53_CRT = "certificates/self-signed/GA-1.01.0.53._.crt";
  private static final String RKI_1 = "certificates/self-signed/RKI-1._.crt";
  private static final String GA_TEST_INT = "certificates/self-signed/GA-Test-Int.cert";

  private LdapNetworkConnection ldapConnection;
  private CertificateDownloaderService underTest;

  private static byte[] getCertificateBytes(final String classpathResource) throws IOException {
    return new ClassPathResource(classpathResource).getInputStream().readAllBytes();
  }

  private static Certificate toCertficate(byte[] bytes) throws CertificateException {
    ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
    return CertificateFactory.getInstance("X.509").generateCertificate(bais);
  }

  private static Stream<Arguments> provideSuccessParams() {
    return Stream.of(
        Arguments.of("1.01.0.53.", "GA-1.01.0.53.", GA_1_01_0_53_CRT),
        Arguments.of("1.", "RKI-1.", RKI_1),
        Arguments.of("test-int", "GA-test-int", GA_TEST_INT) // Testcase: ignore case in CN
        );
  }

  @BeforeEach
  void setup() {
    ldapConnection = mock(LdapNetworkConnection.class);
    when(ldapConnection.getConfig()).thenReturn(mock(LdapConnectionConfig.class));

    underTest = new CertificateDownloaderService(ldapConnection, List.of("1."));
  }

  @ParameterizedTest
  @MethodSource(value = "provideSuccessParams")
  void success(final String userId, final String ldapCn, final String certResource)
      throws Exception {
    final byte[] certificate = getCertificateBytes(certResource);
    setupLdapSearchMock(ldapCn, certificate);

    final Map<String, List<X509Certificate>> result =
        underTest.downloadCertificates(Set.of(userId));
    Assertions.assertThat(result)
        .containsOnlyKeys(userId)
        .extractingByKey(userId, as(InstanceOfAssertFactories.LIST))
        .hasSize(1)
        .first()
        .isEqualTo(toCertficate(certificate));
  }

  @Test
  void validCertificateDoesNotBelongsToRequestedUser() throws Exception {
    final String userId = "3.2.";
    setupLdapSearchMock("GA-" + userId, getCertificateBytes(GA_1_01_0_53_CRT));

    final Map<String, List<X509Certificate>> result =
        underTest.downloadCertificates(Set.of(userId));
    Assertions.assertThat(result).containsExactlyEntriesOf(Map.of(userId, List.of()));
  }

  @Test
  void corruptCertificate() throws Exception {
    final String userId = "3.2.";
    final byte[] corruptCertificate = {1, 2, 3, 4, 5};
    setupLdapSearchMock("GA-" + userId, corruptCertificate);

    final Map<String, List<X509Certificate>> result =
        underTest.downloadCertificates(Set.of(userId));
    Assertions.assertThat(result).containsExactlyEntriesOf(Map.of(userId, List.of()));
  }

  @Test
  void noConnectionToLdap() throws Exception {
    doThrow(LdapException.class).when(ldapConnection).bind();
    final Set<String> param = Set.of("irrelevant");
    assertThatExceptionOfType(CusExecutionException.class)
        .isThrownBy(() -> underTest.downloadCertificates(param))
        .hasFieldOrPropertyWithValue("reason", CusErrorTypeEnum.DTRUST_LDAP)
        .withCauseInstanceOf(LdapException.class);
  }

  private void setupLdapSearchMock(final String userCn, final byte[] certificate)
      throws LdapException {
    final EntryCursor cursor = mock(EntryCursor.class);
    when(ldapConnection.search("C=DE", "(cn=" + userCn + ")", SearchScope.SUBTREE, "*"))
        .thenReturn(cursor);

    final Iterator<Entry> mockIterator = mock(Iterator.class);
    doCallRealMethod().when(cursor).forEach(any());
    when(cursor.iterator()).thenReturn(mockIterator);
    when(mockIterator.hasNext()).thenReturn(true, false);

    final Entry entry = mock(Entry.class);
    when(mockIterator.next()).thenReturn(entry);
    final Attribute attribute = mock(Attribute.class);
    when(entry.get("usercertificate;binary")).thenReturn(attribute);
    when(attribute.getBytes()).thenReturn(certificate);
  }
}
