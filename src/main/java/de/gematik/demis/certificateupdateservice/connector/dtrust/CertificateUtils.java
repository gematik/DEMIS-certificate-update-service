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

import de.gematik.demis.certificateupdateservice.error.CusErrorTypeEnum;
import de.gematik.demis.certificateupdateservice.error.CusExecutionException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Objects;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import lombok.Generated;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

@Slf4j
public class CertificateUtils {

  public static final String X_509 = "X.509";

  private CertificateUtils() {}

  /**
   * Extracts the OCSP URL from the certificate.
   *
   * @param certificate the certificate to extract the OCSP URL from
   * @return the URL of the OCSP server or null if not found
   * @throws IOException in case of an error reading the certificate
   * @throws URISyntaxException in case of an error parsing the URL
   */
  public static URL getOcspUrl(X509Certificate certificate) throws IOException, URISyntaxException {

    final ASN1ObjectIdentifier ocspAccessMethod = X509ObjectIdentifiers.ocspAccessMethod;
    final byte[] authInfoAccessExtensionValue =
        certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
    if (null == authInfoAccessExtensionValue) {
      return null;
    }
    try (ByteArrayInputStream bais = new ByteArrayInputStream(authInfoAccessExtensionValue);
        ASN1InputStream ais1 = new ASN1InputStream(bais);
        ASN1InputStream ais2 =
            new ASN1InputStream(((DEROctetString) (ais1.readObject())).getOctets())) {

      final AuthorityInformationAccess authorityInformationAccess =
          AuthorityInformationAccess.getInstance(ais2.readObject());

      final AccessDescription[] accessDescriptions =
          authorityInformationAccess.getAccessDescriptions();
      for (AccessDescription accessDescription : accessDescriptions) {

        final boolean correctAccessMethod =
            accessDescription.getAccessMethod().equals(ocspAccessMethod);
        final GeneralName gn = accessDescription.getAccessLocation();
        if (!correctAccessMethod || gn.getTagNo() != GeneralName.uniformResourceIdentifier) {
          continue;
        }
        final DERIA5String str =
            (DERIA5String) ((DERTaggedObject) gn.toASN1Primitive()).getBaseObject();
        final String accessLocation = str.getString();
        return new URI(accessLocation).toURL();
      }
      return null;
    }
  }

  /**
   * Loads a certificate from a file.
   *
   * @param filePath the path to the certificate file
   * @return the certificate
   */
  public static X509Certificate loadCertificate(String filePath) {
    try (InputStream caInputStream = new FileInputStream(filePath)) {
      X509Certificate cert =
          (X509Certificate)
              CertificateFactory.getInstance(X_509).generateCertificate(caInputStream);
      log.info("certificate loaded from {}", filePath);
      return cert;
    } catch (Exception ex) {
      throw new CusExecutionException(
          CusErrorTypeEnum.CONFIG, "error loading certificate " + filePath, ex);
    }
  }

  /**
   * Checks that the OCSP response is positive for user.
   *
   * @param response the OCSP response
   * @param userId the user id
   * @return true if the response is positive, false otherwise
   */
  public static boolean isOcspResponsePositive(OCSPResp response, String userId)
      throws OCSPException {

    if (OCSPResp.MALFORMED_REQUEST == response.getStatus()) {
      log.error("{} Malformed request", userId);
      return false;
    }

    if (OCSPResp.SUCCESSFUL != response.getStatus()) {
      log.error("unhandled error for userId {}", userId);
      throw new OCSPException("Server returned error: " + response.getStatus());
    }

    BasicOCSPResp ocspResponseData = (BasicOCSPResp) response.getResponseObject();
    SingleResp[] responses = ocspResponseData.getResponses();
    for (SingleResp response1 : responses) {
      if (response1.getCertStatus() == null) {
        log.info("{} valid certificate found", userId);
        return true;
      } else if (response1.getCertStatus() instanceof RevokedStatus) {
        log.info("{} revoked certificate found", userId);
      }
    }

    return false;
  }

  /**
   * Generates an OCSP request for a certificate.
   *
   * @param clientCert the client certificate
   * @param subCaCert the sub CA certificate
   * @return the OCSP request
   * @throws OCSPReqException in case of an error creating the request
   */
  public static OCSPReq generateOcspRequest(X509Certificate clientCert, X509Certificate subCaCert)
      throws OCSPReqException {
    BigInteger clientCertSerialNumber = clientCert.getSerialNumber();
    try {
      JcaDigestCalculatorProviderBuilder digestCalculatorProviderBuilder =
          new JcaDigestCalculatorProviderBuilder();
      DigestCalculatorProvider digestCalculatorProvider = digestCalculatorProviderBuilder.build();
      DigestCalculator digestCalculator = digestCalculatorProvider.get(CertificateID.HASH_SHA1);

      // Generate the id for the certificate we are looking for
      CertificateID id =
          new CertificateID(
              digestCalculator, new JcaX509CertificateHolder(subCaCert), clientCertSerialNumber);
      OCSPReqBuilder ocspGen = new OCSPReqBuilder().addRequest(id);

      return ocspGen.build();
    } catch (CertificateException | OCSPException | OperatorCreationException e) {
      log.error("Error generateOCSPRequest: {}", e.getMessage());
      throw new OCSPReqException("creating OCSPReq failed", e);
    }
  }

  /**
   * Retrieves the CRL for a certificate.
   *
   * @param certificate the certificate to retrieve the CRL for
   * @return an instance of {@link X509CRL}
   * @throws CertificateException in case of an error reading the certificate
   * @throws IOException in case of an error reading the certificate
   * @throws URISyntaxException in case of an error parsing the URL
   * @throws CRLException in case of an error reading the CRL
   * @throws NamingException in case of an error reading the CRL
   */
  public static X509CRL getRevocationList(final X509Certificate certificate)
      throws CertificateException, IOException, URISyntaxException, CRLException, NamingException {
    final var crlUrl = extractRevocationListUrl(certificate);
    if (Objects.isNull(crlUrl)) {
      throw new CertificateException("No CRL distribution point found in certificate.");
    }

    if (crlUrl.startsWith("ldap://")) {
      return downloadCrlFromLdap(crlUrl);
    }
    return fetchCrlFromHttp(crlUrl);
  }

  /**
   * Extracts the CRL distribution point from a certificate.
   *
   * @param certificate the certificate to extract the CRL distribution point from
   * @return the URL of the CRL distribution point or null if not found
   */
  public static String extractRevocationListUrl(final X509Certificate certificate) {
    try {
      final DistributionPoint[] distributionPoints = getDistributionPoints(certificate);

      // just return the first distribution point
      for (DistributionPoint distributionPoint : distributionPoints) {
        DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
        if (Objects.nonNull(distributionPointName)
            && distributionPointName.getType() == DistributionPointName.FULL_NAME) {
          GeneralNames generalNames = GeneralNames.getInstance(distributionPointName.getName());
          for (GeneralName generalName : generalNames.getNames()) {
            if (generalName.getTagNo() == GeneralName.uniformResourceIdentifier) {
              log.info("CRL distribution point found: {}", generalName.getName().toString());
              return generalName.getName().toString();
            }
          }
        }
      }
      throw new CertificateException("No CRL distribution point found in certificate.");
    } catch (Exception e) {
      log.error("Failed to extract CRL distribution point from certificate: {}", e.getMessage());
      return null;
    }
  }

  static X509CRL downloadCrlFromLdap(final String ldapUrl)
      throws NamingException, CRLException, CertificateException, IOException {
    try (InputStream crlStream = fetchCrlFromLdap(ldapUrl)) {
      CertificateFactory cf = CertificateFactory.getInstance(X_509);
      return (X509CRL) cf.generateCRL(crlStream);
    }
  }

  private static X509CRL fetchCrlFromHttp(final String httpUrl)
      throws IOException, CertificateException, CRLException, URISyntaxException {
    URL url = new URI(httpUrl).toURL();
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    connection.setRequestMethod("GET");
    connection.setDoInput(true);
    connection.connect();

    try (InputStream crlStream = connection.getInputStream()) {
      CertificateFactory cf = CertificateFactory.getInstance(X_509);
      return (X509CRL) cf.generateCRL(crlStream);
    }
  }

  @Generated // Suppress Sonar broken Coverage report
  static DistributionPoint[] getDistributionPoints(X509Certificate certificate)
      throws CertificateException, IOException {
    byte[] crlDistributionPointsExtension =
        certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
    if (Objects.isNull(crlDistributionPointsExtension)) {
      throw new CertificateException("CRL distribution points extension not found in certificate.");
    }

    ASN1Primitive asn1Primitive;
    try (ASN1InputStream asn1InputStream = new ASN1InputStream(crlDistributionPointsExtension)) {
      ASN1Primitive derObject = asn1InputStream.readObject();
      if (derObject instanceof DEROctetString derOctetString) {
        try (ASN1InputStream asn1InputStream2 = new ASN1InputStream(derOctetString.getOctets())) {
          asn1Primitive = asn1InputStream2.readObject();
        }
      } else {
        asn1Primitive = derObject;
      }
    }

    CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(asn1Primitive);
    return crlDistPoint.getDistributionPoints();
  }

  @Generated // Suppress Sonar broken Coverage report
  @SuppressWarnings("java:S1149")
  private static InputStream fetchCrlFromLdap(final String ldapUrl)
      throws NamingException, CRLException {
    var env = new Hashtable<>();
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
    env.put(Context.PROVIDER_URL, ldapUrl);

    DirContext ctx = new InitialDirContext(env);
    String searchFilter = "(objectClass=*)";
    SearchControls searchControls = new SearchControls();
    searchControls.setSearchScope(SearchControls.OBJECT_SCOPE);

    NamingEnumeration<SearchResult> results = ctx.search("", searchFilter, searchControls);
    if (results.hasMore()) {
      SearchResult result = results.next();
      byte[] crlBytes =
          (byte[]) result.getAttributes().get("certificateRevocationList;binary").get();

      return new ByteArrayInputStream(crlBytes);
    }

    throw new CRLException("No CRL found at the specified LDAP URL.");
  }
}
