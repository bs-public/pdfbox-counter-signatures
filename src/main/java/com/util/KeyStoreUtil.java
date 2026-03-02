package com.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;

public class KeyStoreUtil {

  private static final Logger logger = LoggerFactory.getLogger(KeyStoreUtil.class);

  public static KeyStore loadPKCS12(String path, String password) throws Exception {

    logger.info("Loading keystore: {}", path);

    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    try (FileInputStream fis = new FileInputStream(path)) {
      keyStore.load(fis, password.toCharArray());
    }

    return keyStore;
  }

  public static PrivateKey getPrivateKey(KeyStore keyStore, String password) throws Exception {

    String alias = keyStore.aliases().nextElement();
    return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
  }

  public static Certificate[] getCertificateChain(KeyStore keyStore) throws Exception {

    String alias = keyStore.aliases().nextElement();
    return keyStore.getCertificateChain(alias);
  }
}
