package com.ppm.bitmark;

import static com.nimbusds.jose.util.IOUtils.readInputStreamToString;
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
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

public class KeyIOUtils {
  
  static PrivateKey readPrivateKey(String privateKey) throws IOException, GeneralSecurityException {
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
  
  static PrivateKey readPrivateKey(InputStream privateKeyStream) throws IOException, GeneralSecurityException {
    return readPrivateKey(readInputStreamToString(privateKeyStream, StandardCharsets.UTF_8));
  }
  
  static PublicKey readPublicKey(String publicKey) throws GeneralSecurityException, IOException {
    registerBouncyCastleProvider();
    
    Reader privateKeyReader = new StringReader(publicKey);
    PEMParser privatePemParser = new PEMParser(privateKeyReader);
    JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(privatePemParser.readObject());
    return converter.getPublicKey(publicKeyInfo);
  }
  
  static PublicKey readPublicKey(InputStream publicKeyStream) throws IOException, GeneralSecurityException {
    return readPublicKey(readInputStreamToString(publicKeyStream, StandardCharsets.UTF_8));
  }
  
  private static void registerBouncyCastleProvider() {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
  }
  
  static String writePublicKey(PublicKey publicKey) throws IOException {

    try (StringWriter stringWriter = new StringWriter()) {
      try (PemWriter pemWriter = new PemWriter(stringWriter)) {
        pemWriter.writeObject(new PemObject("PUBLIC KEY", publicKey.getEncoded()));
        pemWriter.flush();
        return stringWriter.toString();
      }
    } 
  }

}
