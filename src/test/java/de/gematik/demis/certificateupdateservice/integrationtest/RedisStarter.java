package de.gematik.demis.certificateupdateservice.integrationtest;

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

import lombok.extern.slf4j.Slf4j;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.output.Slf4jLogConsumer;
import org.testcontainers.containers.wait.strategy.Wait;

@Slf4j
public class RedisStarter extends GenericContainer<RedisStarter> {
  private static final int REDIS_PORT = 6379;
  private static final String DOCKER_IMAGE = "redis:7.4.0-alpine";
  private static final String REDIS_TEST_PASSWORD = "passw0rd";
  private static RedisStarter serviceContainer;

  private RedisStarter() {
    super(DOCKER_IMAGE);
  }

  public static int getServicePort() {
    return REDIS_PORT;
  }

  public static String getServicePassword() {
    return REDIS_TEST_PASSWORD;
  }

  public static RedisStarter getServiceContainer() {
    if (serviceContainer == null) {
      serviceContainer =
          new RedisStarter()
              .withLogConsumer(new Slf4jLogConsumer(log))
              .withCommand(
                  "/bin/sh",
                  "-c",
                  String.format(
                      "redis-server --maxmemory 128mb --port 6379 --requirepass %s --bind 0.0.0.0 --loglevel verbose",
                      REDIS_TEST_PASSWORD))
              .withReuse(true)
              .withExposedPorts(REDIS_PORT)
              .waitingFor(
                  Wait.forSuccessfulCommand(
                      String.format("redis-cli -a %s PING || exit 1", REDIS_TEST_PASSWORD)))
              .withStartupAttempts(3);
    }
    return serviceContainer;
  }
}
