package com.sign;

import com.util.KeyStoreUtil;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Date;

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

      int pageIndex = 0;
      float x = 50;
      float y = 600;
      float width = 200;
      float height = 75;

      PDRectangle rect = new PDRectangle(x, y, width, height);

      SignatureOptions signatureOptions = new SignatureOptions();
      signatureOptions.setVisualSignature(createVisualSignatureTemplate(document, pageIndex, rect));
      signatureOptions.setPage(pageIndex);

      document.addSignature(signature, cmsService, signatureOptions);

      document.saveIncremental(fos);
    }
  }

  private static InputStream createVisualSignatureTemplate(
      PDDocument srcDoc, int pageIndex, PDRectangle rect) throws Exception {

    PDDocument doc = new PDDocument();

    PDPage page = new PDPage(srcDoc.getPage(pageIndex).getMediaBox());
    doc.addPage(page);

    PDAcroForm acroForm = new PDAcroForm(doc);
    doc.getDocumentCatalog().setAcroForm(acroForm);

    PDSignatureField signatureField = new PDSignatureField(acroForm);
    PDAnnotationWidget widget = signatureField.getWidgets().get(0);

    widget.setRectangle(rect);
    widget.setPage(page);
    page.getAnnotations().add(widget);

    acroForm.getFields().add(signatureField);

    PDAppearanceDictionary appearance = new PDAppearanceDictionary();
    PDAppearanceStream appearanceStream = new PDAppearanceStream(doc);

    appearanceStream.setResources(new PDResources());
    appearanceStream.setBBox(new PDRectangle(width(rect), height(rect)));

    try (PDPageContentStream cs = new PDPageContentStream(doc, appearanceStream)) {

      cs.beginText();
      cs.setFont(PDType1Font.HELVETICA, 10);
      cs.newLineAtOffset(10, height(rect) - 20);
      cs.showText("Digitally Signed by Signer A");
      cs.newLineAtOffset(0, -15);
      cs.showText("Reason: Test");
      cs.newLineAtOffset(0, -15);
      cs.showText("Date: " + new Date());
      cs.endText();
    }

    appearance.setNormalAppearance(appearanceStream);
    widget.setAppearance(appearance);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    doc.save(baos);
    doc.close();

    return new ByteArrayInputStream(baos.toByteArray());
  }

  private static float width(PDRectangle rect) {
    return rect.getWidth();
  }

  private static float height(PDRectangle rect) {
    return rect.getHeight();
  }
}
