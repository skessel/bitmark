package com.ppm.bitmark;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

@Configuration
@ConfigurationProperties(prefix = "keypairs")
class KeypairConfiguration {
  
  private KeyPairResources authKey;
  private KeyPairResources clientKey;
  
  
  KeyPairResources getAuthKey() {
    return authKey;
  }

  void setAuthKey(KeyPairResources authKey) {
    this.authKey = authKey;
  }

  KeyPairResources getClientKey() {
    return clientKey;
  }

  void setClientKey(KeyPairResources clientKey) {
    this.clientKey = clientKey;
  }

  static class KeyPairResources {
    
    private Resource privateKey;
    private Resource publicKey;
    
    Resource getPrivateKey() {
      return privateKey;
    }
    
    void setPrivateKey(Resource privateKey) {
      this.privateKey = privateKey;
    }
    
    Resource getPublicKey() {
      return publicKey;
    }
    
    void setPublicKey(Resource publicKey) {
      this.publicKey = publicKey;
    }
  }
  
}
