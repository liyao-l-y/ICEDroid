package com.example.app1;


import  android.annotation.SuppressLint;
import android.content.ContentResolver;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import androidx.annotation.NonNull;

import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class  fingerprint {
    //-----------------------------------------------设备------------------------------------------------------
    public String getDeviceID(ContentResolver contentResolver) {
        String s = "设备指纹：\n";
        try {
            // 获取ANDROID_ID
            @SuppressLint("HardwareIds") String androidId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID);
            Log.d("DeviceFingerprint", "Android ID: " + androidId);
            if (androidId != null)
                s += "Android ID：" + androidId + "\n";
        } catch (Exception e) {
            Log.w("getDeviceIDException", e.getMessage(), e);
        }
        return s;
    }



//-----------------------------------------------网络------------------------------------------------------
    public String getLocalMacAddress() {
        String Addr = "网络地址：\n";
        try {
            InetAddress ip = getLocalInetAddress();
            Addr += "当前ip地址:" + ip.toString() + "\n";
            System.out.println("当前ip地址:" + ip);
            byte[] b = NetworkInterface.getByInetAddress(ip).getHardwareAddress();
            System.out.println(NetworkInterface.getByInetAddress(ip));
            StringBuilder buffer = new StringBuilder();
            for (int i = 0; i < b.length; i++) {
                if (i != 0) {
                    buffer.append(':');
                }
                String str = Integer.toHexString(b[i]&0xFF);
                buffer.append(str.length() == 1 ? 0 + str : str);
            }
            Addr += "Mac地址:" + buffer.toString().toLowerCase() + "\n";
        } catch (Exception e) {
            // TODO Auto-generated catch block
            Log.w("getLocalMacAddressException", e.getMessage(),e);
        }

        return Addr;
    }

    private InetAddress getLocalInetAddress() {
        InetAddress ip = null;
        try {
            //列举
            Enumeration<NetworkInterface> en_netInterface = NetworkInterface.getNetworkInterfaces();
            //避免多张网卡
            while (en_netInterface.hasMoreElements()) {//是否还有元素
                NetworkInterface ni = en_netInterface.nextElement();//得到下一个元素
                Enumeration<InetAddress> en_ip = ni.getInetAddresses();//得到一个ip地址的列举
                while (en_ip.hasMoreElements()) {
                    ip = en_ip.nextElement();
                    if (!ip.isLoopbackAddress() && ip instanceof java.net.Inet4Address)
                        break;
                    else
                        ip = null;
                }
                if (ip != null) {
                    break;
                }
            }
        } catch (Exception e) {
            Log.w("getLocalInetAddressException", e.getMessage(),e);
        }
        return ip;
    }

//-----------------------------------------------系统------------------------------------------------------
    public String getSystemProperties() {
        try {
            @SuppressLint("PrivateApi") Class<?> c = Class.forName("android.os.SystemProperties");
            Method get = c.getMethod("get", String.class);

            StringBuilder s = new StringBuilder("系统指纹：\n");

            String[] properties = {
                    "ro.build.fingerprint",
                    "ro.odm.build.fingerprint",
                    "ro.product.build.fingerprint",
                    "ro.system_ext.build.fingerprint",
                    "ro.system.build.fingerprint",
                    "ro.vendor.build.fingerprint",
                    "ro.build.description",

                    "ro.build.date",
                    "ro.build.date.utc",

                    "ro.boot.vbmeta.digest",
                    "ro.boot.cpuid",
                    "ro.boot.flash.locked",
                    "init.svc.bootlogoupdater",
                    "init.svc.pvrsrvinit",
                    "init.svc.servicemanager",
                    "init.svc.vold",
                    "init.svc.netd",
                    "init.svc.netdiag",
                    "init.svc.hald",
                    "init.svc.debuggerd",
                    "init.svc.zygote",
                    "init.svc.drmserver",
                    "init.svc.media",
                    "init.svc.dbus",
                    "init.svc.installd",
                    "init.svc.keystore",
                    "init.svc.console",
                    "init.svc.adbd",
                    "init.svc.ril-daemon",
                    "gsm.version.ril-impl",

            };

            for (String property : properties) {
                String value = (String) get.invoke(c, property);
                if(Objects.equals(value, "")){
                    value = "无结果";
                }
                s.append(property).append(":").append(value).append("\n");
            }
            List<String> p = getSystemProperties2();
            for (String property : p){
                s.append(property).append("\n");
            }

            System.out.println(s);

            return s.toString();
        } catch (Exception e) {
            Log.w("getSystemPropertiesException",  e.getMessage(), e);
        }

        return "系统属性获取失败";
    }

    private List<String> getSystemProperties2(){
        List<String> properties = new ArrayList<>();
        properties.add("BOARD:" + Build.BOARD);
        properties.add("BOOTLOADER:" + Build.BOOTLOADER);
        properties.add("BRAND:" + Build.BRAND);
        properties.add("CPU_ABI:" + Build.CPU_ABI);
        properties.add("DEVICE:" + Build.DEVICE);
        properties.add("DISPLAY:" + Build.DISPLAY);
        properties.add("HARDWARE:" + Build.HARDWARE);
        properties.add("HOST:" + Build.HOST);
        properties.add("ID:" + Build.ID);
        properties.add("MODEL:" + Build.MODEL);
        properties.add("MANUFACTURER:" + Build.MANUFACTURER);
        properties.add("PRODUCT:" + Build.PRODUCT);
        properties.add("RADIO:" + Build.RADIO);
        properties.add("TAGS:" + Build.TAGS);
        properties.add("TIME:" + Build.TIME);
        properties.add("TYPE:" + Build.TYPE);
        properties.add("USER:" + Build.USER);
        properties.add("RELEASE:" + Build.VERSION.RELEASE);
        properties.add("CODENAME:" + Build.VERSION.CODENAME);
        properties.add("INCREMENTAL:" + Build.VERSION.INCREMENTAL);
        properties.add("SDK:" + Build.VERSION.SDK);
        properties.add("SDK_INT:" + Build.VERSION.SDK_INT);

        properties.add("SECURITY_PATCH:" + Build.VERSION.SECURITY_PATCH);
        properties.add("PREVIEW_SDK_INT:" + Build.VERSION.PREVIEW_SDK_INT);
        properties.add("SUPPORTED_ABIS:" + Arrays.toString(Build.SUPPORTED_ABIS));

        properties.add("FINGERPRINT:" + Build.BRAND+"/" + Build.PRODUCT+"/" + Build.DEVICE+":" + Build.VERSION.RELEASE+"/" +
                Build.ID+"/" + Build.VERSION.INCREMENTAL+":" + Build.TYPE+"/" + Build.TAGS);



        return getStrings(properties);
    }


    private @NonNull List<String> getStrings(List<String> properties) {
        List<String> processedProperties = new ArrayList<>();
        for (String property : properties) {
            String[] parts = property.split(":", 2);
            if (parts.length == 2) {
                String key = parts[0];
                String value = parts[1].trim();
                // 替换空值或unknown
                if (value.isEmpty() || value.equalsIgnoreCase("unknown")) {
                    value = "无结果";
                }
                processedProperties.add(key + ":" + value);
            } else {
                // 保留没有冒号的情况
                processedProperties.add(property);
            }
        }
        return processedProperties;
    }


}
