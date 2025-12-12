package com.example.app1;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class signcheck {
    private final Context context;
    private String cer = null;
    private String realCer = null;

    public signcheck(Context context) {
        this.context = context;
        this.cer = getCertificateSHA1Fingerprint();
    }

    public signcheck(Context context, String realCer) {
        this.context = context;
        this.realCer = realCer;
        this.cer = getCertificateSHA1Fingerprint();
    }

    public String getRealCer() {
        return realCer;
    }
    //设置正确的签名
    public void setRealCer(String realCer) {
        this.realCer = realCer;
    }
    //获取应用的签名
    public String getCertificateSHA1Fingerprint() {
        //获取包管理器
        PackageManager pm = context.getPackageManager();
        //获取当前要获取 SHA1 值的包名，也可以用其他的包名，但需要注意，
        //在用其他包名的前提是，此方法传递的参数 Context 应该是对应包的上下文。
        String packageName = context.getPackageName();
        //返回包括在包中的签名信息
        int flags = PackageManager.GET_SIGNATURES;

        PackageInfo packageInfo = null;

        try {
            //获得包的所有内容信息类
            packageInfo = pm.getPackageInfo(packageName, flags);
        } catch (PackageManager.NameNotFoundException e) {
            Log.w("getCertificateSHA1FingerprintException", e.getMessage(),e);
        }
        //签名信息
        assert packageInfo != null;
        Signature[] signatures = packageInfo.signatures;
        byte[] cert = signatures[0].toByteArray();
        //将签名转换为字节数组流
        InputStream input = new ByteArrayInputStream(cert);
        //证书工厂类，实现出厂合格证算法的功能
        CertificateFactory cf = null;

        try {
            cf = CertificateFactory.getInstance("X509");
        } catch (Exception e1) {
            Log.w("getCertificateSHA1FingerprintException", e1.getMessage(),e1);
        }

        //X509证书
        X509Certificate c = null;

        try {
            assert cf != null;
            c = (X509Certificate) cf.generateCertificate(input);
        } catch (Exception e2) {
            Log.w("getCertificateSHA1FingerprintException", e2.getMessage(),e2);
        }

        String hexString = null;

        try {
            //加密算法的类，这里的参数可以使 MD4,MD5 等加密算法
            MessageDigest md = MessageDigest.getInstance("SHA1");
            //获得公钥
            assert c != null;
            byte[] publicKey = md.digest(c.getEncoded());
            //字节到十六进制的格式转换
            hexString = byte2HexFormatted(publicKey);
        } catch (NoSuchAlgorithmException | CertificateEncodingException e3) {
            Log.w("getCertificateSHA1FingerprintException", e3.getMessage(),e3);
        }
        return hexString;
    }

    //这里是将获取到得编码进行16 进制转换
    private String byte2HexFormatted(byte[] arr) {

        StringBuilder str = new StringBuilder(arr.length * 2);

        for (int i = 0; i <arr.length; i++) {
            String h = Integer.toHexString(arr[i]);
            int l =h.length();
            if (l == 1)
                h = "0" + h;
            if (l > 2)
                h = h.substring(l - 2, l);
            str.append(h.toUpperCase());
            if (i < (arr.length - 1))
                str.append(':');
        }
        return str.toString();
    }

    //检测签名是否正确
    public boolean check() {
        if (this.realCer != null) {
            cer = cer.trim();
            Log.d("signcheck", "校验成功");
            realCer = realCer.trim();
            return this.cer.equals(this.realCer);
        }else {
            Log.w("signcheck", "未给定真实的签名 SHA-1 值");
        }
        return false;
    }

}
