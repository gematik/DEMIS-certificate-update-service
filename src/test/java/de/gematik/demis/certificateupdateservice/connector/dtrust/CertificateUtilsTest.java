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
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.gematik.demis.certificateupdateservice.BaseFileLoaderTestHelper;
import de.gematik.demis.certificateupdateservice.error.CusExecutionException;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.naming.CommunicationException;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

@Slf4j
class CertificateUtilsTest extends BaseFileLoaderTestHelper {

  @Test
  void shouldReturnUrlFromCaSubCert() throws IOException, CertificateException {
    X509Certificate x509CertificateFromPath =
        getX509CertificateFromFileName("D-TRUST_Limited_Basic_Test_CA_1-2_2019.crt");
    URL ocspUrl =
        Assertions.assertDoesNotThrow(() -> CertificateUtils.getOcspUrl(x509CertificateFromPath));
    assertThat(ocspUrl.getHost()).isEqualTo("staging.ocsp.d-trust.net");
  }

  @Test
  void shouldLoadCertificate() throws CertificateException {
    X509Certificate x509Certificate =
        CertificateUtils.loadCertificate(
            "src/test/resources/D-TRUST_Limited_Basic_Test_CA_1-2_2019.crt");
    assertThat(x509Certificate).isNotNull().isInstanceOf(X509Certificate.class);
  }

  @Test
  void shouldThrowExceptionWhileLoadCertificateEncountersProblem() throws CertificateException {
    assertThatThrownBy(() -> CertificateUtils.loadCertificate("i do not exists"))
        .isInstanceOf(CusExecutionException.class)
        .hasMessageContaining("error loading certificate i do not exists");
  }

  @Test
  void shouldInterpretOCSPResponseWithOk() throws OCSPException {
    SingleResp response = mock(SingleResp.class);
    when(response.getCertStatus()).thenReturn(null);
    SingleResp[] responses = {response};
    BasicOCSPResp ocspResponseData = mock(BasicOCSPResp.class);
    when(ocspResponseData.getResponses()).thenReturn(responses);

    OCSPResp ocspResponse = mock(OCSPResp.class);
    when(ocspResponse.getResponseObject()).thenReturn(ocspResponseData);
    var valid = CertificateUtils.isOcspResponsePositive(ocspResponse, "someId");
    assertThat(valid).isTrue();
  }

  @Test
  void shouldInterpretOCSPResponseWithRevoked() throws OCSPException {
    SingleResp response = mock(SingleResp.class);
    CertificateStatus revoked = mock(RevokedStatus.class);
    when(response.getCertStatus()).thenReturn(revoked);
    SingleResp[] responses = {response};
    BasicOCSPResp ocspResponseData = mock(BasicOCSPResp.class);
    when(ocspResponseData.getResponses()).thenReturn(responses);

    OCSPResp ocspResponse = mock(OCSPResp.class);
    when(ocspResponse.getResponseObject()).thenReturn(ocspResponseData);
    var valid = CertificateUtils.isOcspResponsePositive(ocspResponse, "someId");
    assertThat(valid).isFalse();
  }

  @Test
  void shouldInterpretOCSPResponseWithMalformedRequest() throws OCSPException {
    OCSPResp ocspResponse = mock(OCSPResp.class);
    when(ocspResponse.getStatus()).thenReturn(1);
    var valid = CertificateUtils.isOcspResponsePositive(ocspResponse, "someId");
    assertThat(valid).isFalse();
  }

  @Test
  void shouldInterpretOCSPResponseWithOtherResponseStatusCode() throws OCSPException {
    OCSPResp ocspResponse = mock(OCSPResp.class);
    when(ocspResponse.getStatus()).thenReturn(2);
    Assertions.assertThrows(
        OCSPException.class, () -> CertificateUtils.isOcspResponsePositive(ocspResponse, "someId"));
  }

  @Test
  void shouldCreateOCSPRequest()
      throws FileNotFoundException, CertificateException, OCSPReqException {

    X509Certificate clientCert =
        getX509CertificateFromFileName("certificates/self-signed/GA-1.01.0.53._.crt");
    X509Certificate subCACert =
        getX509CertificateFromFileName("D-TRUST_Limited_Basic_Test_CA_1-2_2019.crt");
    OCSPReq ocspReq = CertificateUtils.generateOcspRequest(clientCert, subCACert);
    assertThat(ocspReq).isNotNull();
  }

  @Test
  void shouldHandleException() throws FileNotFoundException, CertificateException {

    X509Certificate clientCert =
        getX509CertificateFromFileName("certificates/self-signed/GA-1.01.0.53._.crt");
    X509Certificate subCACert = mock(X509Certificate.class);
    when(subCACert.getEncoded()).thenThrow(new CertificateEncodingException());
    assertThatThrownBy(() -> CertificateUtils.generateOcspRequest(clientCert, subCACert))
        .isInstanceOf(OCSPReqException.class);
  }

  @Test
  void downloadOfCrlFromLdapShouldWork() throws FileNotFoundException, CertificateException {
    final var cert = getX509CertificateFromFileName("D-TRUST_Limited_Basic_Test_CA_1-2_2019.crt");
    final var crl =
        Assertions.assertDoesNotThrow(() -> CertificateUtils.extractRevocationListUrl(cert));
    assertThat(crl).isNotNull();
  }

  @Test
  void extractionOfCrlUrlIsNull() {
    final var crl =
        Assertions.assertDoesNotThrow(() -> CertificateUtils.extractRevocationListUrl(null));
    assertThat(crl).isNull();
  }

  @Test
  void shouldThrowExceptionWhenCrlNotFoundAtLdapUrl() {
    String invalidLdapUrl = "ldap://invalid.url";
    Assertions.assertThrows(
        CommunicationException.class, () -> CertificateUtils.downloadCrlFromLdap(invalidLdapUrl));
  }
}
