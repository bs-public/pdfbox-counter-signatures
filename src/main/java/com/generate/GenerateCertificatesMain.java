package com.generate;

import java.io.FileOutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GenerateCertificatesMain {

  private static final Logger logger = LoggerFactory.getLogger(GenerateCertificatesMain.class);

  private static final String PASSWORD = "password";
  private static final String KEYSTORE_DIR = "keystore";

  public static void main(String[] args) {

    try {
      registerBouncyCastle();

      createKeystoreDirectory();

      generate("signerA.p12", "CN=Signer A, O=Test, C=US");
      generate("signerB.p12", "CN=Signer B, O=Test, C=US");

      logger.info("All certificates generated successfully.");

    } catch (Exception ex) {
      logger.error("Certificate generation failed", ex);
    }
  }

  private static void registerBouncyCastle() {
    if (Security.getProvider("BC") == null) {
      Security.addProvider(new BouncyCastleProvider());
      logger.info("BouncyCastle provider registered.");
    }
  }

  private static void createKeystoreDirectory() throws Exception {
    Path path = Paths.get(KEYSTORE_DIR);
    if (!Files.exists(path)) {
      Files.createDirectories(path);
      logger.info("Created keystore directory: {}", path.toAbsolutePath());
    }
  }

  private static void generate(String fileName, String dn) throws Exception {

    logger.info("Generating certificate for DN: {}", dn);

    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    long now = Instant.now().toEpochMilli();
    X509v3CertificateBuilder certBuilder = buildCertificate(dn, now, keyPair);

    certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));

    ContentSigner contentSigner =
        new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());

    X509Certificate certificate =
        new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(certBuilder.build(contentSigner));

    KeyStore keyStore = KeyStore.getInstance("PKCS12");
    keyStore.load(null, null);

    keyStore.setKeyEntry(
        "alias", keyPair.getPrivate(), PASSWORD.toCharArray(), new Certificate[] {certificate});

    Path outputPath = Paths.get(KEYSTORE_DIR, fileName);

    try (FileOutputStream fos = new FileOutputStream(outputPath.toFile())) {
      keyStore.store(fos, PASSWORD.toCharArray());
    }

    logger.info("Generated keystore: {}", outputPath.toAbsolutePath());
  }

  private static X509v3CertificateBuilder buildCertificate(String dn, long now, KeyPair keyPair) {

    Date notBefore = new Date(now);
    Date notAfter = new Date(now + (10L * 365 * 24 * 60 * 60 * 1000));

    X500Name subject = new X500Name(dn);

    BigInteger serialNumber = new BigInteger(64, new SecureRandom());

    return new JcaX509v3CertificateBuilder(
        subject, serialNumber, notBefore, notAfter, subject, keyPair.getPublic());
  }
}
