package com.ppm.bitmark;

import static com.ppm.bitmark.KeyFingerprinter.sha256Fingerprint;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import org.bouncycastle.crypto.CryptoException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

@Component
class JwtGenerator implements JwtProvider {

  private final KeyPair authKeyPair;
  private final KeyPair clientKeyPair;
  
  public JwtGenerator(KeyPair authKeyPair, KeyPair clientKeyPair) {
    this.authKeyPair = authKeyPair;
    this.clientKeyPair = clientKeyPair;
  }

  @Autowired
  JwtGenerator(KeypairLoader keypairLoader) {
    this(keypairLoader.getAuthKeyPair(), keypairLoader.getClientKeyPair());
  }

  public SignedJWT get() throws JOSEException, CryptoException {

    // Create RSA-signer with the private key
    JWSSigner signer = new RSASSASigner(authKeyPair.getPrivate());

    JWSHeader header = new JWSHeader
        .Builder(new JWSHeader(JWSAlgorithm.RS512))
        .type(JOSEObjectType.JWT)
        .build();
    
    // Prepare JWS object with simple string as payload
    SignedJWT jwt = new SignedJWT(header, buildPayload());
    jwt.sign(signer);

    return jwt;
  }

  private JWTClaimsSet buildPayload() throws CryptoException {

    JWTClaimsSet payload = new JWTClaimsSet.Builder()
        .issuer(sha256Fingerprint(authKeyPair))
        .subject(sha256Fingerprint(clientKeyPair))
        .expirationTime(Date.from(LocalDateTime.now().plusHours(1l).toInstant(ZoneOffset.UTC)))
        .issueTime(new Date())
        .claim("scope", new String[] {"testscope", "decrypt"})
        .claim("ident", "<lanr/ik/bn>")
        .build();

    return payload;
  }
}
