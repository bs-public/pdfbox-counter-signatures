package com.countersign;

import com.util.KeyStoreUtil;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CounterSignPdfMain {

  private static final Logger logger = LoggerFactory.getLogger(CounterSignPdfMain.class);

  public static void main(String[] args) {

    try {
      if (Security.getProvider("BC") == null) {
        Security.addProvider(new BouncyCastleProvider());
      }

      String inputPdf = "pdfs/document-signed-A.pdf";
      String outputPdf = "pdfs/document-signed-A-counter.pdf";
      String keystorePath = "keystore/signerB.p12";
      String password = "password";

      KeyStore keyStore = KeyStoreUtil.loadPKCS12(keystorePath, password);

      PrivateKey privateKey = KeyStoreUtil.getPrivateKey(keyStore, password);

      Certificate[] certificateChain = KeyStoreUtil.getCertificateChain(keyStore);

      counterSign(inputPdf, outputPdf, privateKey, certificateChain);

      logger.info("Counter signature added successfully: {}", outputPdf);

    } catch (Exception e) {
      logger.error("Counter-signing failed", e);
    }
  }

  private static void counterSign(
      String inputPdf, String outputPdf, PrivateKey privateKey, Certificate[] certificateChain)
      throws Exception {

    try (PDDocument document = PDDocument.load(new File(inputPdf));
        FileOutputStream fos = new FileOutputStream(outputPdf)) {

      PDSignature signature = document.getSignatureDictionaries().get(0);

      byte[] cmsBytes = signature.getContents(Files.newInputStream(Paths.get(inputPdf)));

      byte[] updatedCms = addCounterSignature(cmsBytes, privateKey, certificateChain);

      signature.setContents(updatedCms);

      document.saveIncremental(fos);
    }
  }

  private static byte[] addCounterSignature(
      byte[] existingCms, PrivateKey privateKey, Certificate[] certificateChain) throws Exception {

    CMSSignedData cmsSignedData = new CMSSignedData(existingCms);

    SignerInformationStore signerStore = cmsSignedData.getSignerInfos();

    SignerInformation signer = signerStore.getSigners().iterator().next();

    // Build counter signature
    ContentSigner contentSigner =
        new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privateKey);

    SignerInfoGenerator signerInfoGenerator =
        new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
            .build(contentSigner, (java.security.cert.X509Certificate) certificateChain[0]);

    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

    generator.addSignerInfoGenerator(signerInfoGenerator);

    generator.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));

    // Counter-sign the signature value, NOT document
    CMSSignedData counterSignedData =
        generator.generate(new CMSProcessableByteArray(signer.getSignature()), false);

    SignerInformation counterSigner =
        counterSignedData.getSignerInfos().getSigners().iterator().next();

    SignerInformation updatedSigner =
        SignerInformation.addCounterSigners(signer, new SignerInformationStore(counterSigner));

    Collection<SignerInformation> updatedSigners = new ArrayList<>();

    updatedSigners.add(updatedSigner);

    CMSSignedData updatedCms =
        CMSSignedData.replaceSigners(cmsSignedData, new SignerInformationStore(updatedSigners));

    return updatedCms.getEncoded();
  }
}
