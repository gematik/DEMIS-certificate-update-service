package de.gematik.demis.certificateupdateservice.connector.dtrust.helpers;

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

import static de.gematik.demis.certificateupdateservice.connector.dtrust.CertificateUtils.extractRevocationListUrl;
import static de.gematik.demis.certificateupdateservice.connector.dtrust.CertificateUtils.generateOcspRequest;
import static de.gematik.demis.certificateupdateservice.connector.dtrust.CertificateUtils.getRevocationList;
import static de.gematik.demis.certificateupdateservice.connector.dtrust.CertificateUtils.isOcspResponsePositive;
import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.demis.certificateupdateservice.BaseFileLoaderTestHelper;
import de.gematik.demis.certificateupdateservice.connector.dtrust.CertificateUtils;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OnlineCertificateValidatorIntegrationTest extends BaseFileLoaderTestHelper {

  @Mock private X509Certificate mockCertificate;

  @Mock private OcspConnectionTool mockOcspConnectionTool;

  @Mock private OCSPReq mockOcspReq;

  @Mock private OCSPResp mockOcspResp;

  @Mock private X509CRL mockCrl;

  private OnlineCertificateValidator certificateValidator;

  @BeforeEach
  void setUp() {
    MockitoAnnotations.openMocks(this);
    Mockito.reset(mockCertificate, mockOcspConnectionTool, mockOcspReq, mockOcspResp, mockCrl);
    certificateValidator =
        new OnlineCertificateValidator(mockCertificate, 100, mockOcspConnectionTool);
  }

  @Test
  void shouldReturnTrueWhenCertificateIsValidAndNotRevoked() {
    Mockito.when(mockCrl.isRevoked(Mockito.any(X509Certificate.class))).thenReturn(false);
    Mockito.when(mockOcspConnectionTool.sendOcspRequest(Mockito.any()))
        .thenReturn(Optional.of(mockOcspResp));

    try (var certUtil = Mockito.mockStatic(CertificateUtils.class)) {
      certUtil
          .when(() -> getRevocationList(Mockito.any(X509Certificate.class)))
          .thenReturn(mockCrl);

      certUtil
          .when(() -> generateOcspRequest(Mockito.any(), Mockito.any()))
          .thenReturn(mockOcspReq);

      certUtil.when(() -> isOcspResponsePositive(Mockito.any(), Mockito.any())).thenReturn(true);

      // Act
      boolean result = certificateValidator.performOnlineValidation(mockCertificate, "userId");

      // Assert
      assertThat(result).isTrue();
    }
  }

  @Test
  void shouldReturnFalseWhenCertificateIsRevoked() {
    Mockito.when(mockCrl.isRevoked(Mockito.any(X509Certificate.class))).thenReturn(true);
    Mockito.when(mockOcspConnectionTool.sendOcspRequest(Mockito.any()))
        .thenReturn(Optional.of(mockOcspResp));

    try (var certUtil = Mockito.mockStatic(CertificateUtils.class)) {
      certUtil
          .when(() -> getRevocationList(Mockito.any(X509Certificate.class)))
          .thenReturn(mockCrl);

      certUtil
          .when(() -> generateOcspRequest(Mockito.any(), Mockito.any()))
          .thenReturn(mockOcspReq);

      certUtil.when(() -> isOcspResponsePositive(Mockito.any(), Mockito.any())).thenReturn(true);

      // Act
      boolean result = certificateValidator.performOnlineValidation(mockCertificate, "userId");

      // Assert
      assertThat(result).isFalse();
    }
  }

  @Test
  void shouldReturnFalseWhenCheckForRevocationFromCrlFails() {
    Mockito.when(mockOcspConnectionTool.sendOcspRequest(Mockito.any()))
        .thenReturn(Optional.of(mockOcspResp));

    try (var certUtil = Mockito.mockStatic(CertificateUtils.class)) {
      certUtil
          .when(() -> getRevocationList(Mockito.any(X509Certificate.class)))
          .thenThrow(CertificateException.class);

      certUtil
          .when(() -> generateOcspRequest(Mockito.any(), Mockito.any()))
          .thenReturn(mockOcspReq);

      certUtil.when(() -> isOcspResponsePositive(Mockito.any(), Mockito.any())).thenReturn(true);

      // Act
      boolean result = certificateValidator.performOnlineValidation(mockCertificate, "userId");

      // Assert
      assertThat(result).isFalse();
    }
  }

  @Test
  void shouldReturnFalseWhenCheckForRevocationHasNoValidCrlUrl() {
    Mockito.when(mockOcspConnectionTool.sendOcspRequest(Mockito.any()))
        .thenReturn(Optional.of(mockOcspResp));

    try (var certUtil = Mockito.mockStatic(CertificateUtils.class)) {
      certUtil
          .when(() -> extractRevocationListUrl(Mockito.any(X509Certificate.class)))
          .thenReturn(null);

      certUtil
          .when(() -> generateOcspRequest(Mockito.any(), Mockito.any()))
          .thenReturn(mockOcspReq);

      certUtil.when(() -> isOcspResponsePositive(Mockito.any(), Mockito.any())).thenReturn(true);

      // Act
      boolean result = certificateValidator.performOnlineValidation(mockCertificate, "userId");

      // Assert
      assertThat(result).isFalse();
    }
  }

  @Test
  void shouldReturnFalseWhenOcspRequestFails() {
    Mockito.when(mockOcspConnectionTool.sendOcspRequest(Mockito.any()))
        .thenReturn(Optional.of(mockOcspResp));

    try (var certUtil = Mockito.mockStatic(CertificateUtils.class)) {
      certUtil
          .when(() -> getRevocationList(Mockito.any(X509Certificate.class)))
          .thenReturn(mockCrl);

      certUtil
          .when(() -> generateOcspRequest(Mockito.any(), Mockito.any()))
          .thenReturn(mockOcspReq);

      certUtil
          .when(() -> isOcspResponsePositive(Mockito.any(), Mockito.any()))
          .thenThrow(OCSPException.class);

      // Act
      boolean result = certificateValidator.performOnlineValidation(mockCertificate, "userId");

      // Assert
      assertThat(result).isFalse();
    }
  }

  @Test
  void shouldReturnFalseWhenOcspResponseIsNotPositive() throws CertificateException {
    Mockito.when(mockOcspConnectionTool.sendOcspRequest(Mockito.any()))
        .thenReturn(Optional.of(mockOcspResp));

    try (var certUtil = Mockito.mockStatic(CertificateUtils.class)) {
      certUtil
          .when(() -> getRevocationList(Mockito.any(X509Certificate.class)))
          .thenReturn(mockCrl);

      certUtil
          .when(() -> generateOcspRequest(Mockito.any(), Mockito.any()))
          .thenReturn(mockOcspReq);

      certUtil.when(() -> isOcspResponsePositive(Mockito.any(), Mockito.any())).thenReturn(false);

      // Act
      boolean result = certificateValidator.performOnlineValidation(mockCertificate, "userId");

      // Assert
      assertThat(result).isFalse();
    }
  }

  @Test
  void returnNoCertificateForInvalidCert() throws IOException, CertificateException {

    final OnlineCertificateValidator ocspCertificateValidator =
        Assertions.assertDoesNotThrow(() -> new OnlineCertificateValidator(subCa, 100));

    final Map<String, List<X509Certificate>> map = new HashMap<>();
    final X509Certificate userCertToValidate =
        getX509CertificateFromFileName("certificates/self-signed/GA-1.01.0.53._notValid.crt");
    final List<X509Certificate> certList = new ArrayList<>();
    certList.add(userCertToValidate);
    map.put("1.01.0.53.", certList);

    ocspCertificateValidator.validate(map);

    assertThat(map.get("1.01.0.53.")).isEmpty();
  }
}
