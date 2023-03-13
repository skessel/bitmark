package com.ppm.bitmark;

import static com.ppm.bitmark.crypto.Keys.readPublicKey;
import static com.ppm.bitmark.crypto.Keys.writePublicKey;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import com.ppm.bitmark.crypto.AESKey;
import com.ppm.bitmark.crypto.Crypto;
import com.ppm.bitmark.crypto.Keys;

@Component
public class ApiClient {

  private final Logger logger;
  private final JwtProvider jwtProvider;
  private final RestTemplate restTemplate;

  public ApiClient(JwtProvider jwtProvider, RestTemplate restTemplate) {
    this.logger = LoggerFactory.getLogger(getClass());
    this.jwtProvider = jwtProvider;
    this.restTemplate = restTemplate;
    Security.addProvider(new BouncyCastleProvider());
  }

  public String hello() {
    try {

      SignedJWT jwt = jwtProvider.get();
      logger.debug("Try Hello Endpoint with JWT {}", jwt.serialize());

      RequestEntity<Void> request = RequestEntity.get("/hello")
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt.serialize())
          .build();

      ResponseEntity<String> response = restTemplate.exchange(request, String.class);

      logger.debug("Hello Endpoint success", response.getStatusCode().value());
      logger.warn("Status: '{}'", response.getStatusCode().value());
      logger.warn("Body: '{}'", response.getBody());

      return response.getBody();
    } catch (HttpStatusCodeException e) {
      logger.warn("Hello Endpoint failed");
      logger.warn("Status: '{}'", e.getStatusCode().value());
      logger.warn("Message: '{}'", e.getMessage());
      throw new RuntimeException(e);
    } catch (JOSEException | CryptoException e) {
      logger.warn("JWT Generation failed", e);
      throw new RuntimeException(e);
    }

  }

  public PublicKey publicKey(PublicKey publicKey) {

    try {
      SignedJWT jwt = jwtProvider.get();
      logger.debug("Try PublicKey Endpoint with JWT {}", jwt.serialize());

      RequestEntity<String> request = RequestEntity.post("/publickey")
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt.serialize())
          .contentType(MediaType.TEXT_PLAIN)
          .body(writePublicKey(publicKey));

      ResponseEntity<String> response = restTemplate.exchange(request, String.class);
      logger.debug("PublicKey Endpoint success", response.getStatusCode().value());
      logger.warn("Status: '{}'", response.getStatusCode().value());
      logger.warn("Body: '\n{}'", response.getBody());

      return readPublicKey(response.getBody());
    } catch (HttpStatusCodeException e) {
      logger.warn("Hello Endpoint failed");
      logger.warn("Status: '{}'", e.getStatusCode().value());
      logger.warn("Message: '{}'", e.getMessage());
      throw new RuntimeException(e);
    } catch (JOSEException | CryptoException e) {
      logger.warn("JWT Generation failed", e);
      throw new RuntimeException(e);
    } catch (IOException e) {
      logger.warn("Write Public Key failed", e);
      throw new RuntimeException(e);
    } catch (GeneralSecurityException e) {
      logger.warn("Read Public Key failed", e);
      throw new RuntimeException(e);
    }
  }

  public byte[] decrypt(PrivateKey clientPrivateKey, AESKey key, byte[] data) {

    try {
      
      byte[] encryptValue = Crypto.encryptValue(key, data);
      
      SignedJWT jwt = jwtProvider.get();
      logger.debug("Try decrypt Endpoint with JWT {}", jwt.serialize());
      logger.debug("X-Encryption-Cipher-Key {}", key.asBitmarkAesSecret());
      logger.debug("X-Signature {}", Crypto.signature(clientPrivateKey, encryptValue));

      RequestEntity<byte[]> request = RequestEntity.post("/decrypt")
          .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt.serialize())
          .header("X-Encryption-Cipher-Key", key.asBitmarkAesSecret())
          .header("X-Encryption-Version", "oaepgcm")
          .header("X-Signature", Crypto.signature(clientPrivateKey, data))
          .header("X-Signature-Version", "rs512")
          .header("X-Encryption-Compression", "")
          .header("X-Encryption-Content-Type", MediaType.TEXT_PLAIN_VALUE)
          .body(encryptValue);

      ResponseEntity<byte[]> response = restTemplate.exchange(request, byte[].class);
      logger.debug("Decrypt Endpoint success", response.getStatusCode().value());
      logger.warn("Status: '{}'", response.getStatusCode().value());
      logger.debug("X-Encryption-Cipher-Key {}", response.getHeaders().getFirst("X-Encryption-Cipher-Key"));
      logger.debug("X-Signature {}", response.getHeaders().getFirst("X-Signature"));
      
//      Crypto.decryptValue(key, encryptValue);
      
      Keys.readAESKey(
          clientPrivateKey, 
          response.getHeaders().getFirst("X-Encryption-Cipher-Key"),
          response.getHeaders().getFirst("X-Signature"));

      
      return null;
    } catch (HttpStatusCodeException e) {
      logger.warn("Decrypt Endpoint failed");
      logger.warn("Status: '{}'", e.getStatusCode().value());
      logger.warn("Message: '{}'", e.getMessage());
      throw new RuntimeException(e);
    } catch (JOSEException | CryptoException e) {
      logger.warn("JWT Generation failed", e);
      throw new RuntimeException(e);
    } catch (GeneralSecurityException e) {
      logger.warn("Encrption failed", e);
      throw new RuntimeException(e);
    } catch (IOException e) {
      logger.warn("Read AES Key failed", e);
      throw new RuntimeException(e);
    } 
  }
}
