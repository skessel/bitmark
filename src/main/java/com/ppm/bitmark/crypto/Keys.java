package com.ppm.bitmark.crypto;

import static com.nimbusds.jose.util.IOUtils.readInputStreamToString;
import static com.ppm.bitmark.crypto.Base64Utils.decodeBase64;
import static com.ppm.bitmark.crypto.Base64Utils.decodeBase64Url;
import static com.ppm.bitmark.crypto.Base64Utils.encodeBase64;
import static java.util.Objects.nonNull;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.ppm.bitmark.crypto.AESKey.AESKeyImpl;

public class Keys {
  
  public static PrivateKey readPrivateKey(String privateKey) throws IOException, GeneralSecurityException {
    registerBouncyCastleProvider();
    
    Reader privateKeyReader = new StringReader(privateKey);
    KeyFactory factory = KeyFactory.getInstance("RSA");
    PEMParser pemParser = new PEMParser(privateKeyReader);
    PemObject pemObject = pemParser.readPemObject();
    if (nonNull(pemObject)) {
      byte[] content = pemObject.getContent();
      PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
      return factory.generatePrivate(privKeySpec);
    } else {
      throw new IOException("Invalid private key");
    }
  }
  
  public static PrivateKey readPrivateKey(InputStream privateKeyStream) throws IOException, GeneralSecurityException {
    return readPrivateKey(readInputStreamToString(privateKeyStream, StandardCharsets.UTF_8));
  }
  
  public static PublicKey readPublicKey(String publicKey) throws GeneralSecurityException, IOException {
    registerBouncyCastleProvider();
    
    Reader privateKeyReader = new StringReader(publicKey);
    PEMParser privatePemParser = new PEMParser(privateKeyReader);
    JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(privatePemParser.readObject());
    return converter.getPublicKey(publicKeyInfo);
  }
  
  public static PublicKey readPublicKey(InputStream publicKeyStream) throws IOException, GeneralSecurityException {
    return readPublicKey(readInputStreamToString(publicKeyStream, StandardCharsets.UTF_8));
  }
  
  public static String writePublicKey(PublicKey publicKey) throws IOException {
    registerBouncyCastleProvider();
    
    try (StringWriter stringWriter = new StringWriter()) {
      try (PemWriter pemWriter = new PemWriter(stringWriter)) {
        pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
        pemWriter.flush();
        return stringWriter.toString();
      }
    } 
  }
  
  public static AESKey newAESKey(PublicKey publicServerKey) throws GeneralSecurityException , IOException  {
    
    registerBouncyCastleProvider();
    
    byte[] ivBytes = createRandomByteArray(16);
    byte[] keyBytes = createRandomByteArray(32);
    
    SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, "AES");
    GCMParameterSpec ivSpec = new GCMParameterSpec(ivBytes.length * 8, ivBytes);
    
    var base64EncodedIV = encodeBase64(ivBytes);
    var base64EncodedKey = encodeBase64(keyBytes);
    var jsonStructur = new JsonStructur(base64EncodedIV, base64EncodedKey);
    var jsonStructurJson = new ObjectMapper().writeValueAsString(jsonStructur);
    
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
    cipher.init(
        Cipher.ENCRYPT_MODE, 
        publicServerKey, 
        new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSpecified.DEFAULT));

    byte[] bytesToEncrypt = jsonStructurJson.getBytes();
    byte[] encryptionResult = cipher.doFinal(bytesToEncrypt);
    String encodedEncryptionResult = encodeBase64(encryptionResult);
    return new AESKeyImpl(skeySpec, ivSpec, encodedEncryptionResult);
  }
  
  public static AESKey readAESKey(PrivateKey privateKey, String xEncryptedCipherKey, String signature) throws GeneralSecurityException , IOException  {
    
    registerBouncyCastleProvider();
    
    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
    cipher.init(
        Cipher.DECRYPT_MODE, 
        privateKey, 
        new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSpecified.DEFAULT));
    
    byte[] encryptedKeyData = decodeBase64Url(xEncryptedCipherKey);
    byte[] encryptedKeyData2 = decodeBase64(xEncryptedCipherKey);
    
    new String(encryptedKeyData, StandardCharsets.UTF_8);
    
    byte[] decryptedKeyData = cipher.doFinal(encryptedKeyData);
    
    JsonStructur jsonStructur = new ObjectMapper().readValue(decryptedKeyData, JsonStructur.class);
    
    
//    byte[] ivBytes = createRandomByteArray(16);
//    byte[] keyBytes = createRandomByteArray(32);
    
//    SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, "AES");
//    GCMParameterSpec ivSpec = new GCMParameterSpec(ivBytes.length * 8, ivBytes);
//    
//    var base64EncodedIV = encodeBase64(ivBytes);
//    var base64EncodedKey = encodeBase64(keyBytes);
//    var jsonStructur = new JsonStructur(base64EncodedIV, base64EncodedKey);
//    var jsonStructurJson = new ObjectMapper().writeValueAsString(jsonStructur);
//    
//    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
//    cipher.init(
//        Cipher.ENCRYPT_MODE, 
//        privateKey, 
//        new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSpecified.DEFAULT));
//
//    byte[] bytesToEncrypt = jsonStructurJson.getBytes();
//    
//    String encodedEncryptionResult = encodeBase64(encryptionResult);
//    return new AESKeyImpl(skeySpec, ivSpec, encodedEncryptionResult);
    
    return null;
  }
  
  static void registerBouncyCastleProvider() {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }
  
  private static byte[] createRandomByteArray(int lengtInBytes) {
    Random rand = new SecureRandom();
    byte[] bytes = new byte[lengtInBytes];
    rand.nextBytes(bytes);
    return bytes;
  }
  
  final static class JsonStructur {

    @JsonProperty
    private final String base64EncodedKey;
    
    @JsonProperty
    private final String base64EncodedIV;

    @JsonCreator
    JsonStructur(String base64EncodedIV, String base64EncodedKey) {
      this.base64EncodedKey = base64EncodedKey;
      this.base64EncodedIV = base64EncodedIV;
    }
  }

}
