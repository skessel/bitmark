package com.ppm.bitmark.crypto;

import static com.ppm.bitmark.crypto.Base64Utils.encodeBase64;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {
  
  final static String TRANSFORMATION = "AES/GCM/NoPadding";

  /**
   * Encrypts a value by AES/CFB64 algorithm
   *
   * @param symmetricKey the {@link SymmetricKey}
   * @param iv the {@link InitializationVector}
   * @param value  the value to encrypt
   * @return the base 64 encoded encrypted value
   */
  public static String encryptValue(AESKey key, byte[] data) throws GeneralSecurityException {
    
    SecretKeySpec skeySpec = key.getSecretKey();
    IvParameterSpec ivSpec = key.getIvParameter();
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);

    byte[] doFinal = data;
    byte[] bytes = cipher.doFinal(doFinal);

    return Base64Utils.encodeBase64(bytes);
  }
  
  public static byte[] decryptValue(AESKey key, String base64EncryptedData) throws GeneralSecurityException {
    
    SecretKeySpec skeySpec = key.getSecretKey();
    IvParameterSpec ivSpec = key.getIvParameter();
    Cipher cipher = Cipher.getInstance(TRANSFORMATION);
    cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);

    byte[] doFinal = Base64Utils.decodeBase64(base64EncryptedData);
    byte[] bytes = cipher.doFinal(doFinal);

    return bytes;
  }
  
  public static String signature(PrivateKey privateKey, String encryptedData) throws GeneralSecurityException {
    
    Signature privateSignature = Signature.getInstance("SHA512withRSA");
    privateSignature.initSign(privateKey);
    privateSignature.update(encryptedData.getBytes(StandardCharsets.UTF_8));

    byte[] signature = privateSignature.sign();

    return encodeBase64(signature);
  }
  
  static void registerBouncyCastleProvider() {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }
  

}
