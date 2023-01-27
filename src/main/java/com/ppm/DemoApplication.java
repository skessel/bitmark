package com.ppm;

import org.bouncycastle.crypto.CryptoException;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;
import com.nimbusds.jose.JOSEException;
import com.ppm.bitmark.ApiClient;
import com.ppm.bitmark.KeypairLoader;

@SpringBootApplication
public class DemoApplication {

  public static void main(String[] args) throws JOSEException, CryptoException {
    ConfigurableApplicationContext context = SpringApplication.run(DemoApplication.class, args);

    try {
      KeypairLoader keyPairs = context.getBean(KeypairLoader.class);
      ApiClient client = context.getBean(ApiClient.class);
      client.hello();
      client.publicKey(keyPairs.getClientKeyPair().getPublic());
    } catch (Exception e) {
      LoggerFactory.getLogger(DemoApplication.class).error("", e);
    }
  }

  @Bean
  public RestTemplate restTemplate(RestTemplateBuilder builder) {
    return builder
        .uriTemplateHandler(new DefaultUriBuilderFactory("https://wsip-test.bitmarck-daten.de"))
        .build();
  }

}
