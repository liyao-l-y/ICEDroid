package com.example.app1;

import android.util.Log;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class certchain {
    private static final String TAG = "CertChainValidator";
    private final Map<String, X509Certificate> certificateCache = new HashMap<>();



    public List<X509Certificate> buildCertificateChain(X509Certificate leafCert,
                                                       Collection<X509Certificate> intermediateCerts,
                                                       Collection<X509Certificate> rootCerts) {
        List<X509Certificate> chain = new ArrayList<>();
        Set<X509Certificate> visited = new HashSet<>();
        X509Certificate currentCert = leafCert;

        // 创建组合信任库（系统默认 + 自定义根证书）
        Set<X509Certificate> trustAnchors = new HashSet<>(rootCerts);
        trustAnchors.addAll(loadSystemRootCertificates());

        // 创建证书缓存
        cacheCertificates(intermediateCerts);
        cacheCertificates(rootCerts);

        while (currentCert != null) {
            if (visited.contains(currentCert)) {
                Log.w(TAG, "Detected certificate loop: " + currentCert.getSubjectDN());
                break;
            }

            chain.add(currentCert);
            visited.add(currentCert);

            // 检查是否是根证书
            if (isSelfSigned(currentCert)) {
                if (isTrustedRoot(currentCert, trustAnchors)) {
                    Log.i(TAG, "Reached trusted root: " + currentCert.getSubjectDN());
                    return chain;
                }
                break;
            }

            // 查找颁发者
            X509Certificate issuer = findIssuer(currentCert, trustAnchors);
            if (issuer == null) {
                //issuer = findIssuerFromCache(currentCert);
            }

            currentCert = issuer;
        }

        Log.w(TAG, "Incomplete certificate chain");
        return chain; // 可能返回不完整的链，需要上层处理
    }

    private boolean isTrustedRoot(X509Certificate cert, Set<X509Certificate> trustAnchors) {
        try {
            cert.verify(cert.getPublicKey());
            return trustAnchors.stream().anyMatch(ta -> {
                try {
                    cert.verify(ta.getPublicKey());
                    return true;
                } catch (Exception e) {
                    return false;
                }
            });
        } catch (Exception e) {
            return false;
        }
    }

    private void cacheCertificates(Collection<X509Certificate> certificates) {
        for (X509Certificate cert : certificates) {
            String subjectDN = cert.getSubjectX500Principal().getName();
            certificateCache.put(subjectDN, cert);
        }
    }

    private X509Certificate findIssuer(X509Certificate cert, Set<X509Certificate> trustAnchors) {
        String issuerDN = cert.getIssuerX500Principal().getName();
        return certificateCache.getOrDefault(issuerDN, findInTrustAnchors(issuerDN, trustAnchors));
    }

    private X509Certificate findInTrustAnchors(String issuerDN, Set<X509Certificate> trustAnchors) {
        return trustAnchors.stream()
                .filter(cert -> cert.getSubjectX500Principal().getName().equals(issuerDN))
                .findFirst()
                .orElse(null);
    }

    private boolean isSelfSigned(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public Set<X509Certificate> loadSystemRootCertificates() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidCAStore");
            keyStore.load(null, null);

            Set<X509Certificate> systemRoots = new HashSet<>();
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = keyStore.getCertificate(alias);
                if (cert instanceof X509Certificate) {
                    systemRoots.add((X509Certificate) cert);
                }
            }
            return systemRoots;
        } catch (Exception e) {
            Log.e(TAG, "Error loading system roots", e);
            return Collections.emptySet();
        }
    }




}
