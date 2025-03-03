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

import de.gematik.demis.certificateupdateservice.error.CusErrorTypeEnum;
import de.gematik.demis.certificateupdateservice.error.CusExecutionException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import lombok.Generated;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.SystemUtils;
import org.springframework.util.FileSystemUtils;

/** Handles the File Operations for the Certificates. */
@Slf4j
public final class FileManager {

  private FileManager() {}

  /**
   * Loads the Certificates from the given folder.
   *
   * @param sourceFolder the folder where the certificates are stored
   * @return a Map containing the Certificates
   */
  protected static Map<String, X509Certificate> loadCertificatesFromPath(Path sourceFolder) {
    Map<String, X509Certificate> certificates = new HashMap<>();
    try (Stream<Path> paths = Files.walk(sourceFolder)) {
      paths
          .filter(Files::isRegularFile)
          .forEach(
              path -> {
                try (InputStream in = Files.newInputStream(path)) {
                  X509Certificate certificate =
                      (X509Certificate)
                          CertificateFactory.getInstance("X.509").generateCertificate(in);
                  certificates.put(getUserNameFromCertificate(certificate), certificate);
                } catch (Exception e) {
                  log.error("Failed to load certificate from file: {}", path, e);
                }
              });
    } catch (IOException e) {
      log.error("Failed to read certificates from disk", e);
    }
    return certificates;
  }

  /**
   * Writes a Certificate to disk.
   *
   * @param id the Certificate Alias Id
   * @param certificate the content of the certificate in DER Format
   * @param folder the destination folder
   * @throws IOException in case of I/O Error
   */
  protected static void writeToFile(final String id, final byte[] certificate, final Path folder)
      throws IOException {
    File outputFile = new File(folder.resolve(id + ".der").toAbsolutePath().toString());
    Files.write(outputFile.toPath(), certificate);
  }

  /**
   * Deletes a folder and its content, given a path.
   *
   * @param folder the folder to be deleted
   */
  protected static void deleteDirectoryIncludingFiles(final Path folder) {
    try {
      final boolean deleted = FileSystemUtils.deleteRecursively(folder);
      log.info("Directory {} has been deleted: {}", folder, deleted);
    } catch (IOException e) {
      log.warn("Error deleting certificate directory " + folder + ". Please clean manually.", e);
    }
  }

  /**
   * Performs the Synchronization of Folders One-Way, moving the changed files from the source
   * folder to the target one and removing from target folder all the files that are not present in
   * the source one.
   *
   * @param sourceFolder the source folder
   * @param targetFolder the target folder
   * @throws IOException in case of I/O Errors
   */
  protected static void syncFoldersOneWay(final Path sourceFolder, final Path targetFolder)
      throws IOException {
    final Map<Path, String> currentHashes = computeHashes(sourceFolder);
    final Map<Path, String> targetHashes = computeHashes(targetFolder);
    updateTargetEntries(currentHashes, targetHashes, targetFolder);
    removeMissingEntriesFromTargetFolder(targetHashes, currentHashes);
  }

  @Generated // Note: This method is NOT generated. Just to exclude from jacoco easily
  private static void windowsMoveOperationWorkaround(
      final Map<Path, String> sourceHashes,
      final Map<Path, String> targetHashes,
      final Path targetFolder)
      throws IOException {
    log.info("Windows Workaround for AccessDeniedException. Copying files instead of moving.");
    for (var entry : sourceHashes.entrySet()) {
      var matchingTargetElement = findMapEntryFromPath(targetHashes, entry.getKey());
      if (Objects.isNull(matchingTargetElement)
          || !matchingTargetElement.getValue().equalsIgnoreCase(entry.getValue())) {
        final var destination = targetFolder.resolve(entry.getKey().getFileName());
        log.info("Copying {} to {}", entry.getKey(), destination);
        Files.copy(entry.getKey(), destination, StandardCopyOption.REPLACE_EXISTING);
      }
    }
  }

  /**
   * Delete files in destination that are not in present in the map of hashes.
   *
   * @param targetEntries the map containing the Hashes of Files to be compared from
   * @param sourceEntries the map containing the Hashes of Files to be compared to
   */
  private static void removeMissingEntriesFromTargetFolder(
      Map<Path, String> targetEntries, Map<Path, String> sourceEntries) {

    // Reduce the hashMap Keys to hold only filenames without path
    final var fileNames =
        sourceEntries.keySet().stream()
            .map(Path::getFileName)
            .collect(Collectors.toUnmodifiableSet());

    for (Path filePath : targetEntries.keySet()) {
      if (!fileNames.contains(filePath.getFileName())) {
        try {
          log.info("Deleting {}", filePath);
          Files.delete(filePath);
        } catch (IOException e) {
          log.error("Failed to delete {}", filePath, e);
        }
      }
    }
  }

  /**
   * Update the target folder based on hashes computed from source folders. It performs a move
   * operation
   *
   * @param sourceHashes Map containing Path and Hashes
   * @param targetHashes Map containing Path and Hashes
   * @param targetFolder the folder where to store the new files
   * @throws IOException in case of errors
   */
  private static void updateTargetEntries(
      final Map<Path, String> sourceHashes,
      final Map<Path, String> targetHashes,
      final Path targetFolder)
      throws IOException {
    if (SystemUtils.IS_OS_WINDOWS) {
      windowsMoveOperationWorkaround(sourceHashes, targetHashes, targetFolder);
    } else {
      for (var entry : sourceHashes.entrySet()) {
        var matchingTargetElement = findMapEntryFromPath(targetHashes, entry.getKey());
        if (Objects.isNull(matchingTargetElement)
            || !matchingTargetElement.getValue().equalsIgnoreCase(entry.getValue())) {
          final var destination = targetFolder.resolve(entry.getKey().getFileName());
          log.info("Moving {} to {}", entry.getKey(), destination);
          Files.move(entry.getKey(), destination, StandardCopyOption.ATOMIC_MOVE);
        }
      }
    }
  }

  private static Map.Entry<Path, String> findMapEntryFromPath(
      final Map<Path, String> map, final Path path) {
    for (var entry : map.entrySet()) {
      final var entryFileName = entry.getKey().getFileName().toString();
      final var searchFileName = path.getFileName().toString();
      if (entryFileName.equalsIgnoreCase(searchFileName)) {
        return entry;
      }
    }
    return null;
  }

  private static Map<Path, String> computeHashes(final Path folder) throws IOException {
    Map<Path, String> hashes = new HashMap<>();
    try (Stream<Path> fileStream = Files.walk(folder)) {
      fileStream
          .filter(Files::isRegularFile)
          .forEach(
              path -> {
                try (InputStream inputStream = Files.newInputStream(path)) {
                  hashes.put(path, DigestUtils.sha3_256Hex(inputStream));
                } catch (IOException e) {
                  log.error("Failed to compute hash of file", e);
                }
              });
    } catch (Exception exception) {
      throw new CusExecutionException(
          CusErrorTypeEnum.FILESYSTEM,
          "Hash Computation failed with: " + exception.getMessage(),
          exception);
    }
    return hashes;
  }

  private static String getCommonName(final X509Certificate certificate) {
    X500Principal principal = certificate.getSubjectX500Principal();
    String dn = principal.getName();
    String[] dnComponents = dn.split(",");
    for (String component : dnComponents) {
      if (component.trim().startsWith("CN=")) {
        return component.trim().substring(3);
      }
    }
    return null;
  }

  private static String getUserNameFromCertificate(final X509Certificate certificate) {
    final var commonName = Objects.requireNonNull(getCommonName(certificate));
    return commonName.replace("GA-", "").replace("RKI-", "");
  }
}
