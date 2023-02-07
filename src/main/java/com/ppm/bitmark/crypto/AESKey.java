package com.ppm.bitmark.crypto;

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public interface AESKey {
  
  SecretKeySpec getSecretKey();
  
  GCMParameterSpec getIvParameter();

  /**
   * @return a Base64 encoded {@link String} representation of this {@link AESKey}
   */
  String asBitmarkAesSecret();

  static final class AESKeyImpl implements AESKey {

    private final SecretKeySpec key;
    private final GCMParameterSpec iv;
    private final String bitmarkAesSecret;

    AESKeyImpl(SecretKeySpec key, GCMParameterSpec iv, String bitmarkKey)  {
      this.key = key;
      this.iv = iv;
      this.bitmarkAesSecret = bitmarkKey;
    }
    
    @Override
    public SecretKeySpec getSecretKey() {
      return key;
    }
    
    @Override
    public GCMParameterSpec getIvParameter() {
      return iv;
    }
    
    @Override
    public String asBitmarkAesSecret() {
      return bitmarkAesSecret;
    }
  }

}
