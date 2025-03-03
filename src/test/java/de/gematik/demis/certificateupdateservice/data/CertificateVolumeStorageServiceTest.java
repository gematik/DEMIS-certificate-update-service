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

import static org.junit.jupiter.api.Assertions.assertTrue;

import de.gematik.demis.certificateupdateservice.BaseFileLoaderTestHelper;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Objects;
import org.apache.commons.io.FileUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class CertificateVolumeStorageServiceTest extends BaseFileLoaderTestHelper {

  private static final String FOLDER_PATH = System.getProperty("java.io.tmpdir") + "/cus_test";
  private static final String TARGET_FOLDER_PATH = "latest";
  private CertificateVolumeStorageService certificateVolumeStorageService;

  @BeforeEach
  void setUp() {
    certificateVolumeStorageService = new CertificateVolumeStorageService(FOLDER_PATH);
  }

  @AfterEach
  void cleanUp() throws IOException {
    // comment out this line if you wish to inspect the result of the save of the example
    // certificates
    FileUtils.deleteDirectory(new File(FOLDER_PATH));
  }

  @Test
  void shouldLoadCertificatesFromVolumeSuccessfully() throws IOException, URISyntaxException {
    try {
      final var tempDir = Files.createTempDirectory(Path.of("target"), "");
      certificateVolumeStorageService =
          new CertificateVolumeStorageService(tempDir.toAbsolutePath().toString());
      // copy certificates to target folder
      Files.copy(
          Path.of(
              Objects.requireNonNull(
                      classLoader.getResource("certificates/self-signed/GA-1.01.0.53._.crt"))
                  .toURI()),
          tempDir,
          StandardCopyOption.REPLACE_EXISTING);
    } catch (FileAlreadyExistsException e) {
      // Ignore
    }
    Map<String, X509Certificate> loadedCertificates =
        certificateVolumeStorageService.loadCertificatesFromVolume();

    assertTrue(loadedCertificates.containsKey("1.01.0.53."));
  }

  @Test
  void shouldLoadCertificatesFromVolumeWithEmptyFolder() throws IOException {
    Files.createDirectories(Path.of(FOLDER_PATH, TARGET_FOLDER_PATH));

    Map<String, X509Certificate> loadedCertificates =
        certificateVolumeStorageService.loadCertificatesFromVolume();

    assertTrue(
        loadedCertificates.isEmpty(), "No certificates should be loaded from an empty folder");
  }

  @Test
  void shouldLoadCertificatesFromVolumeWithInvalidCertificates() throws IOException {
    Path targetFolderPath = Path.of(FOLDER_PATH, TARGET_FOLDER_PATH);
    Files.createDirectories(targetFolderPath);
    Files.write(targetFolderPath.resolve("invalid.der"), new byte[] {0, 1, 2, 3});

    Map<String, X509Certificate> loadedCertificates =
        certificateVolumeStorageService.loadCertificatesFromVolume();

    assertTrue(loadedCertificates.isEmpty(), "No certificates should be loaded from invalid files");
  }
}
