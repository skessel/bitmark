package com.ppm.bitmark;

import static com.nimbusds.jose.util.IOUtils.readInputStreamToString;
import static java.util.Objects.nonNull;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.util.io.pem.PemObject;
import org.springframework.stereotype.Component;
import com.ppm.bitmark.KeypairConfiguration.KeyPairResources;

@Component
class KeypairLoader {
  
  private final KeyPair authKeyPair;
  private final KeyPair clientKeyPair;
  
  public KeypairLoader(KeypairConfiguration configuration) throws IOException, GeneralSecurityException {
    Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
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
    PrivateKey privateKey = readPrivateKey(resource.getPrivateKey().getInputStream());
    PublicKey publicKey = readPublicKey(resource.getPublicKey().getInputStream());
    return new KeyPair(publicKey, privateKey);
  }
  
  private PrivateKey readPrivateKey(String privateKey) throws IOException, GeneralSecurityException {
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
  
  private PrivateKey readPrivateKey(InputStream privateKeyStream) throws IOException, GeneralSecurityException {
    return readPrivateKey(readInputStreamToString(privateKeyStream, StandardCharsets.UTF_8));
  }
  
  private PublicKey readPublicKey(String publicKey) throws GeneralSecurityException, IOException {
    Reader privateKeyReader = new StringReader(publicKey);
    PEMParser privatePemParser = new PEMParser(privateKeyReader);
    JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(privatePemParser.readObject());
    return converter.getPublicKey(publicKeyInfo);
  }
  
  private PublicKey readPublicKey(InputStream publicKeyStream) throws IOException, GeneralSecurityException {
    return readPublicKey(readInputStreamToString(publicKeyStream, StandardCharsets.UTF_8));
  }

}
