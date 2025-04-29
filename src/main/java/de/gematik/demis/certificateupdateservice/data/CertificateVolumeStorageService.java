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
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Handles the Certificates and stores them on disk. Additionally, it exposes a method for doing a
 * One-Way Synchronization between two folders.
 */
@Service
@Slf4j
public class CertificateVolumeStorageService {

  private final Path rootPath;
  private final FileManager fileManager;

  /**
   * Constructs an instance of this class.
   *
   * @param rootPath the root path where are going to be stored the folders with certificates
   */
  public CertificateVolumeStorageService(
      @Value("${cert.root.folder.path}") String rootPath, FileManager fileManager) {

    this.rootPath = Path.of(rootPath);
    this.fileManager = fileManager;
  }

  /**
   * Loads the certificates from the filesystem.
   *
   * @return the certificates loaded from the filesystem
   */
  public Map<String, X509Certificate> loadCertificatesFromVolume() {
    log.info("Loading Certificates from disk");
    return fileManager.loadCertificatesFromPath(rootPath);
  }
}
