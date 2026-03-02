package com.sign;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.Arrays;

public class CmsSignatureService implements SignatureInterface {

  private final PrivateKey privateKey;
  private final Certificate[] certificateChain;

  public CmsSignatureService(PrivateKey privateKey, Certificate[] certificateChain) {
    this.privateKey = privateKey;
    this.certificateChain = certificateChain;
  }

  @Override
  public byte[] sign(InputStream content) throws IOException {

    try {
      CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

      ContentSigner contentSigner =
          new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privateKey);

      generator.addSignerInfoGenerator(
          new JcaSignerInfoGeneratorBuilder(
                  new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
              .build(contentSigner, (java.security.cert.X509Certificate) certificateChain[0]));

      generator.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));

      CMSTypedData cmsData = new CMSProcessableInputStream(content);

      CMSSignedData signedData = generator.generate(cmsData, false);

      return signedData.getEncoded();

    } catch (Exception e) {
      throw new IOException("CMS signing failed", e);
    }
  }

  private static class CMSProcessableInputStream implements CMSTypedData {

    private final InputStream in;

    CMSProcessableInputStream(InputStream in) {
      this.in = in;
    }

    @Override
    public Object getContent() {
      return in;
    }

    @Override
    public void write(OutputStream out) throws IOException {
      byte[] buffer = new byte[8192];
      int len;
      while ((len = in.read(buffer)) != -1) {
        out.write(buffer, 0, len);
      }
    }

    @Override
    public ASN1ObjectIdentifier getContentType() {
      return CMSObjectIdentifiers.data;
    }
  }
}
