package com.ppm.bitmark;

import org.bouncycastle.crypto.CryptoException;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;

@FunctionalInterface
public interface JwtProvider {
  
  SignedJWT get() throws JOSEException, CryptoException;

}
