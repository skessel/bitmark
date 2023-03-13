package com.ppm;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import org.bouncycastle.crypto.CryptoException;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;
import com.nimbusds.jose.JOSEException;
import com.ppm.bitmark.ApiClient;
import com.ppm.bitmark.KeypairLoader;
import com.ppm.bitmark.crypto.AESKey;
import com.ppm.bitmark.crypto.Keys;

@SpringBootApplication
public class DemoApplication {
  
  private static String plainText = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";

  public static void main(String[] args) throws JOSEException, CryptoException {
    ConfigurableApplicationContext context = SpringApplication.run(DemoApplication.class, args);

    try {
      KeypairLoader keyPairs = context.getBean(KeypairLoader.class);
      ApiClient client = context.getBean(ApiClient.class);
      client.hello();
      
      PublicKey publicServerKey = client.publicKey(keyPairs.getClientKeyPair().getPublic());
      AESKey aesKey = Keys.newAESKey(publicServerKey);
      
      byte[] decrypt = client.decrypt(
          keyPairs.getClientKeyPair().getPrivate(), 
          aesKey, 
          plainText.getBytes(StandardCharsets.UTF_8),
          publicServerKey);
      
      String responseText = new String(decrypt, StandardCharsets.UTF_8);
      
      if (!responseText.equals(plainText)) {
        throw new RuntimeException("Processing not working");
      }
    } catch (Exception e) {
      LoggerFactory.getLogger(DemoApplication.class).error("", e);
    }
  }

  @Bean
  public RestTemplate restTemplate(RestTemplateBuilder builder) {
    return builder
        .requestFactory(HttpComponentsClientHttpRequestFactory.class)
        .uriTemplateHandler(new DefaultUriBuilderFactory("https://wsip-test.bitmarck-daten.de"))
        .build();
  }

}
