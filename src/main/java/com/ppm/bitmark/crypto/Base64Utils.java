package com.ppm.bitmark.crypto;

import java.util.Base64;

class Base64Utils {
  
  private Base64Utils() {};
  
  static byte[] decodeBase64(String data) {
    return Base64.getDecoder().decode(data);
  }
  
  static byte[] decodeBase64Url(String data) {
    return Base64.getUrlEncoder().encode(data.getBytes());
  }

  static String encodeBase64(byte[] bytes) {
    return Base64.getEncoder().encodeToString(bytes);
  }

}
