package com.ppm.bitmark.crypto;

import static com.ppm.bitmark.crypto.Base64Utils.encodeBase64;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
  
  final static String TRANSFORMATION = "AES/GCM/NoPadding";

  public static byte[] encryptValue(AESKey key, byte[] data) throws GeneralSecurityException {
    
    SecretKeySpec skeySpec = key.getSecretKey();
    GCMParameterSpec ivSpec = key.getIvParameter();
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);

    byte[] doFinal = data;
    byte[] bytes = cipher.doFinal(doFinal);

    return bytes;
  }
  
  public static byte[] decryptValue(AESKey key, byte[] data) throws GeneralSecurityException {
    
    SecretKeySpec skeySpec = key.getSecretKey();
    GCMParameterSpec ivSpec = key.getIvParameter();
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);

    byte[] bytes = cipher.doFinal(data);

    return bytes;
  }
  
  public static String createSignatur(PrivateKey privateKey, byte[] rawData) throws GeneralSecurityException {
    
    Signature privateSignature = Signature.getInstance("SHA512withRSA");
    privateSignature.initSign(privateKey);
    privateSignature.update(rawData);

    byte[] signature = privateSignature.sign();

    return encodeBase64(signature);
  }
  
  public static boolean verifySignatur(PublicKey publicKey, byte[] rawData, String signature) throws GeneralSecurityException {
    
    byte[] decodedSignature = Base64Utils.decodeBase64Url(signature);
    
    Signature privateSignature = Signature.getInstance("SHA512withRSA");
    privateSignature.initVerify(publicKey);
    privateSignature.update(rawData);
    boolean verify = privateSignature.verify(decodedSignature);
    
    return verify;
  }
  
  static void registerBouncyCastleProvider() {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }
  

}
