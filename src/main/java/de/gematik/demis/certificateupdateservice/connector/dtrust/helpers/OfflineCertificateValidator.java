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
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

import de.gematik.demis.certificateupdateservice.error.CusErrorTypeEnum;
import de.gematik.demis.certificateupdateservice.error.CusExecutionException;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ContentVerifierProviderBuilder;
import org.bouncycastle.cert.path.CertPath;
import org.bouncycastle.cert.path.CertPathValidation;
import org.bouncycastle.cert.path.CertPathValidationResult;
import org.bouncycastle.cert.path.validations.BasicConstraintsValidation;
import org.bouncycastle.cert.path.validations.KeyUsageValidation;
import org.bouncycastle.cert.path.validations.ParentCertIssuedValidation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Validates certificates offline against the CA and SubCA certificates. */
@Slf4j
public class OfflineCertificateValidator {

  private final Supplier<Date> currentDateProvider;
  private final X509CertificateHolder subCaCertHold;
  private final X509CertificateHolder caCertHold;

  public OfflineCertificateValidator(X509Certificate caCert, X509Certificate subCaCert) {
    this(caCert, subCaCert, Date::new);
  }

  public OfflineCertificateValidator(
      X509Certificate caCert, X509Certificate subCaCert, Supplier<Date> currentDateProvider) {
    this.currentDateProvider = currentDateProvider;
    Security.addProvider(new BouncyCastleProvider());

    try {
      this.subCaCertHold = new X509CertificateHolder(subCaCert.getEncoded());
      this.caCertHold = new X509CertificateHolder(caCert.getEncoded());
    } catch (IOException | CertificateEncodingException e) {
      throw new CusExecutionException(
          CusErrorTypeEnum.CONFIG, "Error initializing the offline validator", e);
    }
  }

  /**
   * Validates the certificates offline against the CA and SubCA certificates. Removes all the
   * invalid certificates from the map.
   *
   * @param userCertificates the map of user ids and their certificates
   */
  public void offlineValidation(final Map<String, List<X509Certificate>> userCertificates) {
    for (var entry : userCertificates.entrySet()) {
      var userCerts = entry.getValue();
      if (!userCerts.isEmpty()) {
        userCerts.removeIf(
            x509Certificate -> !validateUserCertificate(x509Certificate, entry.getKey()));
      }
    }
  }

  private boolean validateUserCertificate(X509Certificate userCert, String userId) {
    try {
      userCert.checkValidity(currentDateProvider.get());

      X509CertificateHolder userCertHold = new X509CertificateHolder(userCert.getEncoded());

      CertPath path =
          new CertPath(new X509CertificateHolder[] {userCertHold, subCaCertHold, caCertHold});
      CertPathValidationResult result = path.validate(createRuleset());

      if (result.isValid()) {
        return true;
      }

      final String o1 =
          result.getCause() != null ? result.getCause().getMessage() : "no cause given";
      log.info("{} certificate with offline validation cause: {}", userId, o1);
      return false;
    } catch (CertificateExpiredException e) {
      log.info("{} certificate expired", userId);
      return false;
    } catch (CertificateNotYetValidException e) {
      log.info("{} certificate not yet valid", userId);
      return false;
    } catch (CertificateException | IOException e) {
      log.error("{} certificate through unexpected exception: {}", userId, e.getLocalizedMessage());
      log.debug(e.getLocalizedMessage(), e);
      return false;
    }
  }

  private CertPathValidation[] createRuleset() {
    return new CertPathValidation[] {
      new ParentCertIssuedValidation(
          new JcaX509ContentVerifierProviderBuilder()
              .setProvider(BouncyCastleProvider.PROVIDER_NAME)),
      new BasicConstraintsValidation(),
      new KeyUsageValidation()
    };
  }
}
