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

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPResp;

@Slf4j
public class OcspConnectionTool implements Closeable {

  private final URL ocspUrl;
  private HttpURLConnection connection;
  private OutputStream output;
  private InputStream input;

  public OcspConnectionTool(URL ocspUrl) {
    this.ocspUrl = ocspUrl;
  }

  @Override
  public void close() throws IOException {
    input.close();
    output.close();
    connection.disconnect();
  }

  public Optional<OCSPResp> sendOcspRequest(byte[] request) {
    try {
      connection = (HttpURLConnection) ocspUrl.openConnection();
      connection.setDoOutput(true);
      connection.setDoInput(true);
      connection.setRequestProperty("Content-Type", "application/ocsp-request");
      connection.setRequestProperty("Accept", "application/ocsp-response");
      connection.setRequestProperty("Content-Length", String.valueOf(request.length));

      output = connection.getOutputStream();
      output.write(request);

      input = connection.getInputStream();
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      byte[] buffer = new byte[1024];
      int bytesRead = 0;
      while ((bytesRead = input.read(buffer, 0, buffer.length)) >= 0) {
        baos.write(buffer, 0, bytesRead);
      }

      byte[] respBytes = baos.toByteArray();
      close();
      return Optional.of(new OCSPResp(respBytes));
    } catch (IOException e) {
      log.error("OcspConnectionTool failed while sending: {}", e.getLocalizedMessage());
      return Optional.empty();
    }
  }
}
