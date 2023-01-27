package com.ppm.bitmark;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

class PublicKeyFingerprinter {
  
  static String sha256FingerprintString(PublicKey key) {
    try {
      return Base64.getEncoder().withoutPadding().encodeToString(sha256Fingerprint(key));
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
  
 private static byte[] sha256Fingerprint(PublicKey key) throws NoSuchAlgorithmException, IOException {
    return messageDigest("SHA-256", encode(key));
  }
  
  private static byte[] messageDigest(String algo, byte[] bytes) throws NoSuchAlgorithmException {
    return MessageDigest.getInstance(algo).digest(bytes);
  }
  
  private static byte[] encode(PublicKey publicKey) throws IOException {
    if (publicKey instanceof RSAPublicKey) {
      return encode((RSAPublicKey) publicKey);
    }
    throw new RuntimeException("unknown or unsupported public key type: " + publicKey.getClass().getName());
  }
  
  private static byte[] encode(RSAPublicKey publicKey) throws IOException {
    byte[] name = "ssh-rsa".getBytes(StandardCharsets.US_ASCII);
    byte[] exponent = publicKey.getPublicExponent().toByteArray();
    byte[] modulus = publicKey.getModulus().toByteArray();
    
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
    outputStream.write(name);
    outputStream.write(exponent);
    outputStream.write(modulus);

    return outputStream.toByteArray( );
    
  }
}
