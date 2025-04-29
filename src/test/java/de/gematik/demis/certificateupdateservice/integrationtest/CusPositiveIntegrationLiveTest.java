package de.gematik.demis.certificateupdateservice.integrationtest;

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

import static org.assertj.core.api.Assertions.assertThat;

import de.gematik.demis.certificateupdateservice.CertificateUpdateServiceApplication;
import de.gematik.demis.certificateupdateservice.data.CertificateDataEntity;
import de.gematik.demis.certificateupdateservice.data.CertificateRepository;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.SoftAssertions;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.ldap.AutoConfigureDataLdap;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(
    classes = {CertificateUpdateServiceApplication.class, TestConfig.class},
    webEnvironment = SpringBootTest.WebEnvironment.NONE)
@ActiveProfiles(profiles = "live-integrationtest")
@AutoConfigureWireMock(port = 0, files = "integrationtest/wiremock")
@AutoConfigureDataLdap
@Slf4j
class CusPositiveIntegrationLiveTest {

  private static final Path SOURCE_CERTIFICATES =
      Path.of("src/test/resources/certificates/self-signed/expected");
  private static final RedisStarter redisServiceContainer = RedisStarter.getServiceContainer();

  @Autowired private CertificateRepository repository;

  @DynamicPropertySource
  static void startRedisAndConfigureProperties(DynamicPropertyRegistry propertyRegistry) {
    redisServiceContainer.start();

    propertyRegistry.add("spring.data.redis.host", redisServiceContainer::getHost);
    propertyRegistry.add(
        "spring.data.redis.port",
        () -> redisServiceContainer.getMappedPort(RedisStarter.getServicePort()));
    propertyRegistry.add("spring.data.redis.password", RedisStarter::getServicePassword);
    propertyRegistry.add("cert.root.folder.path", SOURCE_CERTIFICATES::toString);
  }

  private static Set<Path> getFilesOfDirectory(final Path dir) throws IOException {
    try (final Stream<Path> stream = Files.list(dir)) {
      return stream.filter(file -> !Files.isDirectory(file)).collect(Collectors.toSet());
    }
  }

  @AfterAll
  static void tearDown() {
    redisServiceContainer.stop();
  }

  @Test
  void run() throws IOException {
    // Note: the command line runner is already executed at this point
    // just some assertions here
    final Map<String, Path> expectedCerts =
        getFilesOfDirectory(SOURCE_CERTIFICATES).stream()
            .collect(Collectors.toMap(p -> p.getFileName().toString(), Function.identity()));

    assertCertsStoredInRedis(expectedCerts);
  }

  private void assertCertsStoredInRedis(final Map<String, Path> expectedCerts) {
    final Map<String, CertificateDataEntity> all =
        StreamSupport.stream(repository.findAll().spliterator(), false)
            .collect(Collectors.toMap(e -> e.id() + ".der", Function.identity()));
    assertThat(all.keySet()).isNotEmpty();

    final SoftAssertions assertions = new SoftAssertions();
    for (final var entry : all.entrySet()) {
      final var expectedCert = expectedCerts.get(entry.getKey());
      assertions
          .assertThatPath(expectedCert)
          .hasBinaryContent(entry.getValue().encodedCertificate());
    }
    assertions.assertAll();
  }
}
