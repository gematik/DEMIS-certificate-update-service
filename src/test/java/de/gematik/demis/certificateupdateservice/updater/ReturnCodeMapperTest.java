package de.gematik.demis.certificateupdateservice.updater;

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

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.gematik.demis.certificateupdateservice.error.CusErrorTypeEnum;
import de.gematik.demis.certificateupdateservice.error.CusExecutionException;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.boot.ExitCodeExceptionMapper;

class ReturnCodeMapperTest {
  public static Stream<Arguments> valueProvider() {
    return Stream.of(
        Arguments.of(1, new Exception(new RuntimeException("Generic exception"))),
        Arguments.of(1, new RuntimeException("Generic exception")),
        Arguments.of(2, new CusExecutionException(CusErrorTypeEnum.CONFIG, "message")),
        Arguments.of(3, new CusExecutionException(CusErrorTypeEnum.KEYCLOAK, "message")),
        Arguments.of(4, new CusExecutionException(CusErrorTypeEnum.DTRUST_LDAP, "message")),
        Arguments.of(
            5, new CusExecutionException(CusErrorTypeEnum.CERTIFICATE_ENCODING, "message")),
        Arguments.of(6, new CusExecutionException(CusErrorTypeEnum.REDIS, "message")),
        Arguments.of(7, new CusExecutionException(CusErrorTypeEnum.FILESYSTEM, "message")));
  }

  @ParameterizedTest
  @MethodSource("valueProvider")
  void testExitCodeToExceptionMapper(final int expectedExitCode, final Exception exception) {
    // Create an instance of the ExitCodeExceptionMapper
    ExitCodeExceptionMapper mapper =
        new CertificateUpdateConfiguration().exitCodeToExceptionMapper();

    // Test different exception scenarios and assert the expected exit codes
    assertEquals(expectedExitCode, mapper.getExitCode(exception));
  }
}
