package com.example.app1;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;


public class rootcheck {
    //root检测
    //检查SU命令能否执行
    public String checkSuCommand() {
        Process process = null;
        try {
            // 尝试运行su命令
            process = Runtime.getRuntime().exec("which su" );
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = in.readLine();
            System.out.println(line);
            return line; // su命令执行成功，可能被Root
        } catch (Exception e) {
            Log.w("checkSuCommandException", e.getMessage(),e);
            return e.toString(); // 执行su命令失败，可能未Root
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }
    //检查root文件是否存在
    public String checkRootFiles() {
        String[] rootFilesPaths = {
                "/system/app/Superuser.apk",
                "/sbin/su",
                "/system/bin/su",
                "/system/xbin/su",
                "/data/local/bin/su",
                "/magisk",
                "/data/adb/magisk",
        };
        StringBuilder result = new StringBuilder();
        for (String path : rootFilesPaths) {
            if (new File(path).exists()) {
                result.append(path).append(":已发现").append("\n"); // 发现Root相关文件
            }else {
                result.append(path).append(":未发现").append("\n");
            }
        }
        return result.toString();
    }
    //检查系统属性
    public String checkSystemTags() {
        try {
            // 读取ro.build.tags系统属性
            String buildTags = Build.TAGS;
            System.out.println(buildTags);
            return buildTags;
        } catch (Exception e) {
            // 读取系统属性失败
            return e.toString();
        }
    }
    //检查分区读写模式
    public String checkMountInfo() {
        try {
            Process process = Runtime.getRuntime().exec("mount");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder result = new StringBuilder();
            while ((line = in.readLine())!= null) {
                if (line.contains("system")) {
                    result.append(line); // /system分区被挂载为读写模式，可能是Root设备
                }
            }
            return result.toString();
        } catch (Exception e) {
            return e.toString();
        }
    }
    //检查系统属性
    public String checkSystemProperty() {
        String debuggable = getSystemProperty("ro.debuggable");
        String secure = getSystemProperty("ro.secure");
        return "ro.debuggable:" + debuggable + "\n" +
               "ro.secure:" + secure;
    }
    //获取系统属性值。
    private String getSystemProperty(String key) {
        String value = null;
        try {
            Process process = Runtime.getRuntime().exec("getprop " + key);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            value = reader.readLine();
        } catch (Exception e) {
            Log.w("getSystemPropertyException", e.getMessage(),e);
        }
        return value;
    }
    //检测SELinux状态
    public String getSELinuxStatus() {
        try {
            Process process = Runtime.getRuntime().exec("getenforce");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = in.readLine();
            System.out.println(line);
            return line != null ? line.trim() : "unknown"; // 安全处理null值
        } catch (Exception e) {
            Log.w("getSELinuxStatusException", e.getMessage(), e);
            return e.toString(); // 检测失败
        }
    }
    //检测bootloader
    public String isBootloaderLocked() {
        try {
            String result = "unknown";
            Process process = Runtime.getRuntime().exec("getprop ro.boot.verifiedbootstate");
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            if ((line = reader.readLine()) != null) {
                System.out.println(line);
                result = line;
            }
            reader.close();
            process.waitFor();
            System.out.println(result);
            return result;
        } catch (Exception e) {
            Log.w("BootloaderChecker", "Error checking bootloader status", e);
            return e.toString();
        }
    }
    //检测TEE状态
    @RequiresApi(api = Build.VERSION_CODES.TIRAMISU)
    public String checkTEE() {
        try {
            // 从 Android Keystore 中获取密钥
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            // 生成一个非对称密钥对（RSA）如果还没有的话
            if (!keyStore.containsAlias("rsa_test_key")) {
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");
                keyPairGenerator.initialize(
                        new KeyGenParameterSpec.Builder(
                                "rsa_test_key",
                                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                                .build());
                keyPairGenerator.generateKeyPair();
            }
            // 获取生成的密钥对
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("rsa_test_key", null);
            // 使用 KeyFactory 获取 KeyInfo
            KeyFactory keyFactory = KeyFactory.getInstance(privateKeyEntry.getPrivateKey().getAlgorithm(), "AndroidKeyStore");
            KeyInfo keyInfo = keyFactory.getKeySpec(privateKeyEntry.getPrivateKey(), KeyInfo.class);
            // 检查密钥是否存储在安全硬件中（即 TEE 中）
            System.out.println(keyInfo.isInsideSecureHardware());
            return keyInfo.isInsideSecureHardware() ? "密钥存储于TEE中" : "密钥未存储于TEE中";
        } catch (NoSuchAlgorithmException | CertificateException | IOException |
                 InvalidKeySpecException | NoSuchProviderException |
                 InvalidAlgorithmParameterException | UnrecoverableEntryException |
                 KeyStoreException e) {
            Log.w("checkTEEException", e.getMessage(),e);
            return e.toString();
        }
    }
}
