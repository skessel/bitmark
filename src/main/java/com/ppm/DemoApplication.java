package com.ppm;

import org.bouncycastle.crypto.CryptoException;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;
import com.nimbusds.jose.JOSEException;
import com.ppm.bitmark.ApiClient;

@SpringBootApplication
public class DemoApplication {

  public static void main(String[] args) throws JOSEException, CryptoException {
    ConfigurableApplicationContext context = SpringApplication.run(DemoApplication.class, args);

    try {
      ApiClient client = context.getBean(ApiClient.class);
      client.hello();
    } catch (Exception e) {
      LoggerFactory.getLogger(DemoApplication.class).error("", e);
    }
  }

  @Bean
  public RestTemplate restTemplate(RestTemplateBuilder builder) {
    return builder.build();
  }

}
