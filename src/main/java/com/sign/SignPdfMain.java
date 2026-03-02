package com.sign;

import com.util.KeyStoreUtil;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Calendar;

public class SignPdfMain {

  private static final Logger logger = LoggerFactory.getLogger(SignPdfMain.class);

  public static void main(String[] args) {

    try {
      if (Security.getProvider("BC") == null) {
        Security.addProvider(new BouncyCastleProvider());
      }

      String inputPdf = "pdfs/document.pdf";
      String outputPdf = "pdfs/document-signed-A.pdf";
      String keystorePath = "keystore/signerA.p12";
      String password = "password";

      KeyStore keyStore = KeyStoreUtil.loadPKCS12(keystorePath, password);

      PrivateKey privateKey = KeyStoreUtil.getPrivateKey(keyStore, password);

      Certificate[] certificateChain = KeyStoreUtil.getCertificateChain(keyStore);

      CmsSignatureService cmsService = new CmsSignatureService(privateKey, certificateChain);

      signPdf(inputPdf, outputPdf, cmsService);

      logger.info("PDF signed successfully: {}", outputPdf);

    } catch (Exception e) {
      logger.error("PDF signing failed", e);
    }
  }

  private static void signPdf(String inputPdf, String outputPdf, CmsSignatureService cmsService)
      throws Exception {

    try (PDDocument document = PDDocument.load(new File(inputPdf));
        FileOutputStream fos = new FileOutputStream(outputPdf)) {

      PDSignature signature = new PDSignature();
      signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
      signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);

      signature.setName("Signer A");
      signature.setLocation("Test");
      signature.setReason("Test");
      signature.setSignDate(Calendar.getInstance());

      document.addSignature(signature, cmsService);

      document.saveIncremental(fos);
    }
  }
}
