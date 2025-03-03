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
 * #L%
 */

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.demis.certificateupdateservice.BaseFileLoaderTestHelper;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.SystemUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@Slf4j
class FileManagerTest extends BaseFileLoaderTestHelper {

  private static final String ROOT_PATH =
      System.getProperty("java.io.tmpdir")
          + "/cus_test"
          + RandomStringUtils.secure().nextAlphanumeric(10);
  private static final String TARGET_FOLDER_PATH = "latest";

  private static final String SOURCE_FOLDER_PATH = "newcerts";

  private static Path sourcePath;
  private static Path targetPath;

  @BeforeAll
  protected static void beforeAll() {
    final var rootPath = Path.of(ROOT_PATH);
    sourcePath = rootPath.resolve(SOURCE_FOLDER_PATH);
    targetPath = rootPath.resolve(TARGET_FOLDER_PATH);
  }

  @SneakyThrows
  @BeforeEach
  void setUp() {
    final var rootPath = Path.of(ROOT_PATH);
    if (!Files.exists(rootPath)) {
      Files.createDirectory(rootPath);
    }
    log.info("## Test Start");
  }

  @AfterEach
  void cleanUp() throws IOException {
    // comment out this line if you wish to inspect the result of the save of the example
    // certificates
    FileUtils.deleteDirectory(new File(ROOT_PATH));
    log.info("## Test completed");
  }

  @Test
  void expectStoreCertificatesSuccessfully() {
    log.info("expectStoreCertificatesSuccessfully");
    // GIVEN A List of certificates
    final var certList = Assertions.assertDoesNotThrow(this::getValidCertificates);
    // WHEN certificates are written to disk
    Assertions.assertDoesNotThrow(() -> persistCertificatesOnDisk(certList, sourcePath));
    // THEN Files must be existing
    assertTrue(
        new File(sourcePath.toAbsolutePath().toString(), "1.01.0.53..der").exists(),
        "File 1.01.0.53..der missing");
    assertTrue(
        new File(sourcePath.toAbsolutePath().toString(), "1..der").exists(), "File 1..der missing");
  }

  @Test
  void expectDeleteEmptyFolderWorksSuccessfully() {
    log.info("expectDeleteEmptyFolderWorksSuccessfully");
    // WHEN a new Folder is created
    final var createdFolder =
        Assertions.assertDoesNotThrow(() -> Files.createDirectories(sourcePath));
    // AND it is deleted
    FileManager.deleteDirectoryIncludingFiles(createdFolder);
    // THEN the folder doesn't exist anymore
    assertFalse(Files.exists(createdFolder), "The folder should be deleted");
  }

  @Test
  void expectDeleteFolderWithFilesWorksSuccessfully() {
    log.info("expectDeleteFolderWithFilesWorksSuccessfully");
    // GIVEN A List of certificates
    final var sourceCertificates = Assertions.assertDoesNotThrow(this::getValidCertificates);
    // WHEN certificates are written to disk
    Assertions.assertDoesNotThrow(() -> persistCertificatesOnDisk(sourceCertificates, sourcePath));
    // AND it is deleted
    FileManager.deleteDirectoryIncludingFiles(sourcePath);
    // THEN the folder doesn't exist anymore
    assertFalse(Files.exists(sourcePath), "The folder should be deleted");
  }

  @Test
  void expectSynchronizeFoldersSuccessfullyWithAlreadyExistingButSameTargetCerts()
      throws IOException {
    log.info("expectSynchronizeFoldersSuccessfullyWithAlreadyExistingButSameTargetCerts");
    // GIVEN A List of certificates
    final var sourceCertificates = Assertions.assertDoesNotThrow(this::getValidCertificates);
    final var targetCertificates = Assertions.assertDoesNotThrow(this::getValidCertificates);
    // WHEN certificates are written to disk
    Assertions.assertDoesNotThrow(() -> persistCertificatesOnDisk(targetCertificates, targetPath));
    Assertions.assertDoesNotThrow(() -> persistCertificatesOnDisk(sourceCertificates, sourcePath));
    // THEN Files must be existing in Both Folders
    assertTrue(
        new File(sourcePath.toAbsolutePath().toString(), "1.01.0.53..der").exists(),
        "File 1.01.0.53..der missing");
    // THEN Files must be existing in Both Folders
    assertTrue(
        new File(targetPath.toAbsolutePath().toString(), "1.01.0.53..der").exists(),
        "File 1.01.0.53..der missing");
    // WHEN The OneWaySync is triggered
    Assertions.assertDoesNotThrow(() -> FileManager.syncFoldersOneWay(sourcePath, targetPath));
    // THEN check that files are fine
    Assertions.assertTrue(
        new File(targetPath.toAbsolutePath().toString(), "1.01.0.53..der").exists(),
        "File 1.01.0.53..der missing");
    Assertions.assertTrue(
        new File(targetPath.toAbsolutePath().toString(), "1..der").exists(), "File 1..der missing");
    // AND They are the same
    assertArrayEquals(
        Files.readAllBytes(sourcePath.resolve("1.01.0.53..der")),
        Files.readAllBytes(targetPath.resolve("1.01.0.53..der")),
        "Files content must be the same");
  }

  @Test
  void expectSynchronizeFoldersSuccessfullyWithAlreadyExistingButDifferentTargetCerts()
      throws IOException {
    log.info("expectSynchronizeFoldersSuccessfullyWithAlreadyExistingButDifferentTargetCerts");
    // GIVEN A List of certificates
    final var sourceCertificates = Assertions.assertDoesNotThrow(this::getValidCertificates);
    final var targetCertificates = Assertions.assertDoesNotThrow(this::getOtherCertificates);
    // WHEN certificates are written to disk
    Assertions.assertDoesNotThrow(() -> persistCertificatesOnDisk(targetCertificates, targetPath));
    Assertions.assertDoesNotThrow(() -> persistCertificatesOnDisk(sourceCertificates, sourcePath));
    // THEN Files must be existing in Both Folders
    assertTrue(
        new File(sourcePath.toAbsolutePath().toString(), "1.01.0.53..der").exists(),
        "File 1.01.0.53..der missing in source folder");
    assertTrue(
        new File(targetPath.toAbsolutePath().toString(), "1.01.0.53..der").exists(),
        "File 1.01.0.53..der missing in target folder");
    // AND they are different
    assertFalse(
        Arrays.equals(
            Files.readAllBytes(sourcePath.resolve("1.01.0.53..der")),
            Files.readAllBytes(targetPath.resolve("1.01.0.53..der"))),
        "Content of files is the same but it should be different");
    // WHEN The OneWaySync is triggered
    Assertions.assertDoesNotThrow(() -> FileManager.syncFoldersOneWay(sourcePath, targetPath));
    // THEN check that files are fine
    Assertions.assertTrue(
        new File(targetPath.toAbsolutePath().toString(), "1.01.0.53..der").exists(),
        "File 1.01.0.53..der missing in the target folder");
    Assertions.assertTrue(
        new File(targetPath.toAbsolutePath().toString(), "1..der").exists(),
        "File 1..der missing in the target folder");
    if (SystemUtils.IS_OS_WINDOWS) {
      // AND They are the same (on Windows is only copied)
      assertArrayEquals(
          Files.readAllBytes(sourcePath.resolve("1.01.0.53..der")),
          Files.readAllBytes(targetPath.resolve("1.01.0.53..der")),
          "Files content must be the same");
    } else {
      // AND The file changed is not existing anymore in the source folder (moved)
      Assertions.assertFalse(
          new File(sourcePath.toAbsolutePath().toString(), "1.01.0.53..der").exists(),
          "File 1.01.0.53..der should not exist in the source folder");
      Assertions.assertTrue(
          new File(sourcePath.toAbsolutePath().toString(), "1..der").exists(),
          "File 1..der should not exist in the source folder");
    }
  }

  @Test
  void expectSynchronizeFoldersSuccessfullyWithEmptyTargetFolder() throws IOException {
    log.info("expectSynchronizeFoldersSuccessfullyWithEmptyTargetFolder");
    // GIVEN A List of certificates
    final var sourceCertificates = Assertions.assertDoesNotThrow(this::getValidCertificates);
    // WHEN certificates are written to disk
    Assertions.assertDoesNotThrow(() -> persistCertificatesOnDisk(sourceCertificates, sourcePath));
    if (!Files.exists(targetPath)) {
      Assertions.assertDoesNotThrow(() -> Files.createDirectory(targetPath));
    }
    // THEN Files must be existing in Source Folder
    assertTrue(
        new File(sourcePath.toAbsolutePath().toString(), "1.01.0.53..der").exists(),
        "File 1.01.0.53..der missing from source folder");
    // AND They don't exist in Target Folder
    assertFalse(
        new File(targetPath.toAbsolutePath().toString(), "1.01.0.53..der").exists(),
        "File 1.01.0.53..der should not exist in the target folder");
    // WHEN The OneWaySync is triggered
    Assertions.assertDoesNotThrow(() -> FileManager.syncFoldersOneWay(sourcePath, targetPath));
    // THEN check that files are copied
    Assertions.assertTrue(
        new File(targetPath.toAbsolutePath().toString(), "1.01.0.53..der").exists(),
        "File 1.01.0.53..der missing from target folder");
    Assertions.assertTrue(
        new File(targetPath.toAbsolutePath().toString(), "1..der").exists(),
        "File 1..der missing from target folder");
    if (SystemUtils.IS_OS_WINDOWS) {
      // AND They are the same (on Windows is only copied)
      assertArrayEquals(
          Files.readAllBytes(sourcePath.resolve("1.01.0.53..der")),
          Files.readAllBytes(targetPath.resolve("1.01.0.53..der")),
          "Files content must be the same");
    } else {
      // AND The file is not existing anymore in the source folder (moved)
      Assertions.assertFalse(
          new File(sourcePath.toAbsolutePath().toString(), "1.01.0.53..der").exists(),
          "File 1.01.0.53..der should not exist in the source folder");
      Assertions.assertFalse(
          new File(sourcePath.toAbsolutePath().toString(), "1..der").exists(),
          "File 1..der should not exist in the source folder");
    }
  }

  @Test
  void expectSynchronizeFoldersSuccessfullyAndRemoveNotExistingFromTargetFolder() {
    log.info("expectSynchronizeFoldersSuccessfullyAndRemoveNotExistingFromTargetFolder");
    // GIVEN A List of certificates
    final var sourceCertificates = Assertions.assertDoesNotThrow(this::getValidCertificates);
    // remove one from source first
    sourceCertificates.remove(1);
    final var targetCertificates = Assertions.assertDoesNotThrow(this::getOtherCertificates);
    // WHEN certificates are written to disk
    Assertions.assertDoesNotThrow(() -> persistCertificatesOnDisk(targetCertificates, targetPath));
    Assertions.assertDoesNotThrow(() -> persistCertificatesOnDisk(sourceCertificates, sourcePath));
    // THEN File must be existing in target Folder only
    assertFalse(
        new File(sourcePath.toAbsolutePath().toString(), "1..der").exists(),
        "File 1..der should not be present from source folder");
    assertTrue(
        new File(targetPath.toAbsolutePath().toString(), "1..der").exists(),
        "File 1..der should not be missing from target folder");
    // WHEN The OneWaySync is triggered
    Assertions.assertDoesNotThrow(() -> FileManager.syncFoldersOneWay(sourcePath, targetPath));
    // THEN check that files are deleted
    assertFalse(
        new File(sourcePath.toAbsolutePath().toString(), "1..der").exists(),
        "File 1..der should not be present from source folder");
    assertFalse(
        new File(targetPath.toAbsolutePath().toString(), "1..der").exists(),
        "File 1..der should not be present from target folder");
  }

  @Test
  void expectLoadCertificatesFromDiskWorksSuccessfully() {
    log.info("expectLoadCertificatesFromDiskSuccessfully");
    // GIVEN A List of certificates
    final var certList = Assertions.assertDoesNotThrow(this::getValidCertificates);
    // WHEN certificates are written to disk
    Assertions.assertDoesNotThrow(() -> persistCertificatesOnDisk(certList, sourcePath));
    // THEN load certificates from disk
    Map<String, X509Certificate> loadedCertificates =
        FileManager.loadCertificatesFromPath(sourcePath);
    // AND verify the loaded certificates
    assertTrue(loadedCertificates.containsKey("1.01.0.53."), "Certificate 1.01.0.53..der missing");
    assertTrue(loadedCertificates.containsKey("1."), "Certificate 1..der missing");
  }

  @Test
  void expectLoadCertificatesFromDiskWithEmptyFolderHasNoCertificates() {
    log.info("expectLoadCertificatesFromDiskWithEmptyFolder");
    // GIVEN an empty folder
    Assertions.assertDoesNotThrow(() -> Files.createDirectories(sourcePath));
    // WHEN load certificates from disk
    Map<String, X509Certificate> loadedCertificates =
        FileManager.loadCertificatesFromPath(sourcePath);
    // THEN verify no certificates are loaded
    assertTrue(
        loadedCertificates.isEmpty(), "No certificates should be loaded from an empty folder");
  }

  @Test
  void expectLoadCertificatesFromDiskWithInvalidCertificatesHasNoCertificates() throws IOException {
    log.info("expectLoadCertificatesFromDiskWithInvalidCertificates");
    // GIVEN a folder with invalid certificate files
    Assertions.assertDoesNotThrow(() -> Files.createDirectories(sourcePath));
    Files.write(sourcePath.resolve("invalid.der"), new byte[] {0, 1, 2, 3});
    // WHEN load certificates from disk
    Map<String, X509Certificate> loadedCertificates =
        FileManager.loadCertificatesFromPath(sourcePath);
    // THEN verify no certificates are loaded
    assertTrue(loadedCertificates.isEmpty(), "No certificates should be loaded from invalid files");
  }

  // Gives a set of valid certificates
  private List<CertificateDataEntity> getValidCertificates() throws CertificateEncodingException {
    final var cert1 =
        Assertions.assertDoesNotThrow(
            () -> getX509CertificateFromFileName("certificates/self-signed/GA-1.01.0.53._.crt"));
    final var cert2 =
        Assertions.assertDoesNotThrow(
            () -> getX509CertificateFromFileName("certificates/self-signed/RKI-1._.crt"));

    final var certList = new ArrayList<CertificateDataEntity>();
    certList.add(new CertificateDataEntity("1.01.0.53.", cert1.getEncoded(), LocalDateTime.now()));
    certList.add(new CertificateDataEntity("1.", cert2.getEncoded(), LocalDateTime.now()));
    return certList;
  }

  // Gives a set of other certificates for testing purpose (not correct)
  private List<CertificateDataEntity> getOtherCertificates() throws CertificateEncodingException {
    final var cert1 =
        Assertions.assertDoesNotThrow(
            () ->
                getX509CertificateFromFileName(
                    "certificates/self-signed/GA-1.01.0.53._notValid.crt"));
    final var cert2 =
        Assertions.assertDoesNotThrow(
            () -> getX509CertificateFromFileName("certificates/self-signed/RKI-1._.crt"));

    final var certList = new ArrayList<CertificateDataEntity>();
    certList.add(new CertificateDataEntity("1.01.0.53.", cert1.getEncoded(), LocalDateTime.now()));
    certList.add(new CertificateDataEntity("1.", cert2.getEncoded(), LocalDateTime.now()));
    return certList;
  }

  private void persistCertificatesOnDisk(
      final List<CertificateDataEntity> certificates, final Path folder) throws IOException {
    if (!Files.exists(folder)) {
      Files.createDirectory(folder);
    }
    // AND certificates are written to disk
    for (var entry : certificates) {
      Assertions.assertDoesNotThrow(
          () -> FileManager.writeToFile(entry.id(), entry.encodedCertificate(), folder));
    }
  }
}
