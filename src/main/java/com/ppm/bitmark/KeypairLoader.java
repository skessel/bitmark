package com.ppm.bitmark;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.springframework.stereotype.Component;
import com.ppm.bitmark.KeypairConfiguration.KeyPairResources;
import com.ppm.bitmark.crypto.Keys;

@Component
public class KeypairLoader {
  
  private final KeyPair authKeyPair;
  private final KeyPair clientKeyPair;
  
  public KeypairLoader(KeypairConfiguration configuration) throws IOException, GeneralSecurityException {
    this.authKeyPair = asKeyPair(configuration.getAuthKey());
    this.clientKeyPair = asKeyPair(configuration.getClientKey());
  }
  
  public KeyPair getAuthKeyPair() {
    return authKeyPair;
  }
  
  public KeyPair getClientKeyPair() {
    return clientKeyPair;
  }
  
  private KeyPair asKeyPair(KeyPairResources resource) throws IOException, GeneralSecurityException {
    PrivateKey privateKey = Keys.readPrivateKey(resource.getPrivateKey().getInputStream());
    PublicKey publicKey = Keys.readPublicKey(resource.getPublicKey().getInputStream());
    return new KeyPair(publicKey, privateKey);
  }
  
 

}
