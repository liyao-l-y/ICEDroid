package com.example.app1;

import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;


public class keyattestion {
    static final String ASN1_OID = "1.3.6.1.4.1.11129.2.1.17";
    StringBuilder karesult = new StringBuilder("★KeyAttestion★\n");
    private boolean isdevicelocked;
    public String checkcertchain() {
        //-------------------------------生成证书链-------------------------------------------
        try {
            try {
                // 从 Android Keystore 中获取密钥
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);

                // 检查密钥是否已存在
                if (!keyStore.containsAlias("ec_key")) {
                    System.out.println("开始生成密钥");
                    try {
                        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

                        // 先尝试带认证挑战的方式
                        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                                "ec_key",
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                                .setDigests(KeyProperties.DIGEST_SHA256,
                                        KeyProperties.DIGEST_SHA384,
                                        KeyProperties.DIGEST_SHA512);

                        // 首先尝试不带认证挑战的方式
                        keyPairGenerator.initialize(builder.build());
                        KeyPair keyPair = keyPairGenerator.generateKeyPair();

                        System.out.println("密钥生成成功");
                    } catch (Exception e) {
                        System.out.println("带认证的密钥生成失败，尝试备选方案");
                        e.printStackTrace();

                        // 如果失败，尝试生成没有认证挑战的密钥
                        try {
                            KeyPairGenerator fallbackGenerator = KeyPairGenerator.getInstance(
                                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                            KeyGenParameterSpec fallbackSpec = new KeyGenParameterSpec.Builder(
                                    "ec_key_fallback",
                                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                                    .setDigests(KeyProperties.DIGEST_SHA256)
                                    .build();

                            fallbackGenerator.initialize(fallbackSpec);
                            KeyPair fallbackKeyPair = fallbackGenerator.generateKeyPair();
                            System.out.println("备选密钥生成成功");
                        } catch (Exception fallbackEx) {
                            System.out.println("备选密钥也生成失败");
                            fallbackEx.printStackTrace();
                        }
                    }
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            //--------------------------------------获取证书---------------------------------------------------
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            Certificate[] certs = keyStore.getCertificateChain("ec_key");//证书链
            StringBuilder certchain = new StringBuilder("证书链\n---------------------------------\n");
            if (certs == null) {
                Log.e("KeyAttestation", "Certificate chain is null");
                // 根据需要返回错误状态或使用默认值
                return "Certificate chain is null";
            }
            for(Certificate cert : certs){
                X509Certificate x509c = (X509Certificate) cert;
                String subjectDN = x509c.getSubjectDN().getName();  // 使用者
                String issuerDN = x509c.getIssuerDN().getName();    // 颁发者
                String validity = x509c.getNotBefore() + " - " + x509c.getNotAfter(); // 有效期

                certchain.append("Subject:").append(subjectDN).append("\n");
                certchain.append("Issuer:").append(issuerDN).append("\n");
                certchain.append("Validity:").append(validity).append("\n");
                certchain.append("---------------------------------").append("\n");
            }
            X509Certificate x509Cert = (X509Certificate) certs[0];//获取含有1.3.6.1.4.1.11129.2.1.17extension的证书
            //--------------------------------------解析证书---------------------------------------------------
            byte[] attestationExtensionBytes = x509Cert.getExtensionValue(ASN1_OID);

            if (attestationExtensionBytes == null) {
                System.out.println("未找到认证扩展数据");
                return certchain + "\n\n该设备不支持密钥认证或无法获取认证信息";
            }

            ASN1Sequence seq = getAsn1SequenceFromBytes(attestationExtensionBytes);
            //------------------KeyDescription-----------------------
            keydescription kd = new keydescription();
            String KeyDescription = kd.keyDescriptionResult(seq);
            //------------------AuthorizationList-----------------------
            keyauthorizationlist ka = new keyauthorizationlist();
            String AuthorizationList = ka.AuthorizationList(seq);
            isdevicelocked = ka.isdevicelocked;
            karesult.append(certchain).append("\n\n").append(KeyDescription).append("\n\n").append(AuthorizationList);
            return karesult.toString();
        } catch (NoSuchAlgorithmException | CertificateException | IOException |
                 java.security.KeyStoreException e) {
            Log.w("checkcertchainException", e.getMessage(),e);
        }
        return "解析失败";
    }
    public boolean isDeviceLocked(){
        return isdevicelocked;
    }
//---------------------------------------------------getdataFromAsn1------------------------------------------------
    public static ASN1Sequence getAsn1SequenceFromBytes(byte[] bytes)
            throws CertificateParsingException {
        try (ASN1InputStream asn1InputStream = new ASN1InputStream(bytes)) {
            return getAsn1SequenceFromStream(asn1InputStream);
        } catch (IOException e) {
            throw new CertificateParsingException("Failed to parse SEQUENCE", e);
        }
    }
    public static ASN1Sequence getAsn1SequenceFromStream(final ASN1InputStream asn1InputStream)
            throws IOException, CertificateParsingException {
        ASN1Primitive asn1Primitive = asn1InputStream.readObject();
        if (!(asn1Primitive instanceof ASN1OctetString)) {
            throw new CertificateParsingException(
                    "Expected octet stream, found " + asn1Primitive.getClass().getName());
        }
        try (ASN1InputStream seqInputStream = new ASN1InputStream(
                ((ASN1OctetString) asn1Primitive).getOctets())) {
            asn1Primitive = seqInputStream.readObject();
            if (!(asn1Primitive instanceof ASN1Sequence)) {
                throw new CertificateParsingException(
                        "Expected sequence, found " + asn1Primitive.getClass().getName());
            }
            return (ASN1Sequence) asn1Primitive;
        }
    }
}
