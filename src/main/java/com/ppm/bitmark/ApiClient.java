package com.ppm.bitmark;

import static org.springframework.web.util.UriComponentsBuilder.fromHttpUrl;
import java.net.URI;
import java.security.Security;
import org.bouncycastle.crypto.CryptoException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;

@Component
public class ApiClient {

  private final Logger logger;
  private final JwtProvider jwtProvider;
  private final RestTemplate restTemplate;

  public ApiClient(JwtProvider jwtProvider, RestTemplate restTemplate) {
    this.logger = LoggerFactory.getLogger(getClass());
    this.jwtProvider = jwtProvider;
    this.restTemplate = restTemplate;
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }
  
  public String hello() {
    
    try {
      
      SignedJWT jwt = jwtProvider.get();
      
      logger.debug("Try Hello Endpoint with JWT {}", jwt.serialize());
      
      URI helloUri = fromHttpUrl("https://wsip.bitmarck-daten.de")
        .path("/hello")
        .build()
        .toUri();
      
      RequestEntity<Void> request = RequestEntity.get(helloUri)
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

//  public PublicKey publicKey(PublicKey publicKey) {
//
//    try (StringWriter stringWriter = new StringWriter()) {
//      try(PemWriter pemWriter = new PemWriter(stringWriter)) {
//        pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
//        stringWriter.toString().getBytes(UTF_8);
//      }
//      
//    } catch (Exception e) {
//      // TODO: handle exception
//    }
//    
//    return null;
//  }

}
