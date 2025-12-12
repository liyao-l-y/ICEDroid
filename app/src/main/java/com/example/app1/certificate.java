package com.example.app1;

import static com.google.common.reflect.Reflection.getPackageName;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.AsyncTask;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class certificate {
    public String listInstalledCertificates() {
        StringBuilder cert = new StringBuilder("证书信息\n---------------------------------\n");
        try {
            // 获取Android系统的KeyStore
            KeyStore keyStore = KeyStore.getInstance("AndroidCAStore");
            keyStore.load(null, null); // 加载密钥库

            // 遍历所有证书别名
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = keyStore.getCertificate(alias);
                if (certificate instanceof X509Certificate x509c) {
                    // 提取证书信息
                    String subjectDN = x509c.getSubjectDN().getName();  // 使用者
                    String issuerDN = x509c.getIssuerDN().getName();    // 颁发者
                    String validity = x509c.getNotBefore() + " - " + x509c.getNotAfter(); // 有效期

                    cert.append("Alias:").append(alias).append("\n");
                    cert.append("Subject:").append(subjectDN).append("\n");
                    cert.append("Issuer:").append(issuerDN).append("\n");
                    cert.append("Validity:").append(validity).append("\n");
                    cert.append("---------------------------------").append("\n");
                }
            }
        } catch (Exception e) {
            Log.w("checkcertException", e.getMessage(),e);
        }
        //listInstalledCertificates1();
        return cert.toString();
    }
//------------------------------------------------------------------------------------------------------------------------
    public void listInstalledCertificates1() {
        try {
            // 获取Android系统的KeyStore
            KeyStore keyStore = KeyStore.getInstance("AndroidCAStore");
            keyStore.load(null, null); // 加载密钥库

            // 存储所有证书
            List<X509Certificate> certificates = new ArrayList<>();

            // 遍历所有证书别名并存储X509证书
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = keyStore.getCertificate(alias);
                if (certificate instanceof X509Certificate) {
                    certificates.add((X509Certificate) certificate);
                }
            }

            // 打印证书链
            for (X509Certificate cert : certificates) {
                System.out.println("Certificate: " + cert.getSubjectDN().getName());
                printCertificateChain(cert, certificates);
                System.out.println("---------------------------------");
            }
        } catch (Exception e) {
            Log.w("checkcertException", e.getMessage(),e);
        }
    }

    private void printCertificateChain(X509Certificate cert, List<X509Certificate> allCertificates) {
        List<X509Certificate> chain = new ArrayList<>();
        X509Certificate currentCert = cert;

        // 构建证书链
        while (currentCert != null) {
            chain.add(currentCert);
            currentCert = findIssuer(currentCert, allCertificates);
        }

        // 输出证书链
        for (X509Certificate c : chain) {
            System.out.println(" - " + c.getSubjectDN().getName() + " (Issuer: " + c.getIssuerDN().getName() + ")");
        }
    }

    private X509Certificate findIssuer(X509Certificate cert, List<X509Certificate> allCertificates) {
        String issuerDN = cert.getIssuerDN().getName();
        for (X509Certificate c : allCertificates) {
            if (c.getSubjectDN().getName().equals(issuerDN)) {
                return c;
            }
        }
        return null; // 找不到颁发者
    }
//-----------------------------------------------证书链----------------------------------------------------------------
    @SuppressLint("StaticFieldLeak")
    public void validateAppCertificateChainSimple(Context context) {
        new AsyncTask<Void, Void, List<X509Certificate>>() {
            @Override
            protected List<X509Certificate> doInBackground(Void... voids) {
                try {
                    X509Certificate leafCert = getAppSignatureCertificate(context);
                    if (leafCert == null) return null;
                    // 加载系统信任库
                    KeyStore keyStore = KeyStore.getInstance("AndroidCAStore");
                    keyStore.load(null, null);
                    // 构建证书缓存
                    Map<String, X509Certificate> certCache = new HashMap<>();
                    Enumeration<String> aliases = keyStore.aliases();
                    while (aliases.hasMoreElements()) {
                        Certificate cert = keyStore.getCertificate(aliases.nextElement());
                        if (cert instanceof X509Certificate x509Cert) {
                            certCache.put(x509Cert.getSubjectDN().getName(), x509Cert);
                        }
                    }
                    // 构建证书链
                    List<X509Certificate> chain = new ArrayList<>();
                    X509Certificate current = leafCert;
                    Set<X509Certificate> visited = new HashSet<>();
                    while (current != null && !visited.contains(current)) {
                        chain.add(current);
                        visited.add(current);
                        String issuerDN = current.getIssuerDN().getName();
                        current = certCache.get(issuerDN);
                    }

                    return chain;

                } catch (Exception e) {
                    Log.e("CertChain", "Validation error", e);
                    return null;
                }
            }
            @Override
            protected void onPostExecute(List<X509Certificate> certChain) {
                StringBuilder result = new StringBuilder();

                if (certChain == null || certChain.isEmpty()) {
                    result.append("无法获取证书链");
                } else {
                    result.append("证书链（从应用证书到根证书）：\n\n");
                    for (int i = 0; i < certChain.size(); i++) {
                        X509Certificate cert = certChain.get(i);
                        result.append("层级 ").append(i + 1).append(":\n")
                                .append("主题：").append(cert.getSubjectDN()).append("\n")
                                .append("颁发者：").append(cert.getIssuerDN()).append("\n")
                                .append("有效期：").append(cert.getNotBefore()).append(" - ")
                                .append(cert.getNotAfter()).append("\n\n");
                    }

                    // 检查根证书有效性
                    X509Certificate rootCert = certChain.get(certChain.size()-1);
                    if (!isSelfSigned(rootCert)) {
                        result.append("\n警告：根证书可能不受信任！");
                    }
                }
                System.out.println(result.toString());
            }
            private boolean isSelfSigned(X509Certificate cert) {
                try {
                    cert.verify(cert.getPublicKey());
                    return true;
                } catch (Exception e) {
                    return false;
                }
            }
        }.execute();
    }

    private X509Certificate getAppSignatureCertificate(Context context) {
        try {
            String packageName = getPackageName(context.getClass());
            PackageInfo packageInfo = context.getPackageManager()
                    .getPackageInfo(packageName, PackageManager.GET_SIGNATURES);

            Signature[] signatures = packageInfo.signatures;
            byte[] certBytes = signatures[0].toByteArray();
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (Exception e) {
            Log.e("CertUtils", "Error getting app certificate", e);
            return null;
        }
    }



}
