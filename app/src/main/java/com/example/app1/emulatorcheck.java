package com.example.app1;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.BatteryManager;
import android.os.Build;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Objects;

public class emulatorcheck {
    //模拟器检测
    //检查设备指纹
    public String checkfingerprint(){
        try {
            @SuppressLint("PrivateApi") Class<?> c = Class.forName("android.os.SystemProperties");
            Method get = c.getMethod("get", String.class);
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
            };
            StringBuilder result = new StringBuilder();
            for (String property : properties) {
                String value = (String) get.invoke(c, property);
                if(Objects.equals(value, "")){
                    continue;
                }
                assert value != null;
                if (value.contains("x86")) {
                    System.out.println(value);
                    result.append(value);
                }
            }
            return result.toString();
        } catch (Exception e) {
            Log.w("getSystemPropertiesException",  e.getMessage(), e);
            return e.toString();
        }
    }
    //检查设备属性
    public String checkBuild() {
        String board = "BOARD:" + Build.BOARD;
        String brand = "BRAND:" + Build.BRAND;
        String abi = "CPU_ABI:" + Build.CPU_ABI;
        String device = "DEVICE:" + Build.DEVICE;
        String model = "MODEL:" + Build.MODEL;
        String product = "PRODUCT:" + Build.PRODUCT;
        String support = "SUPPORTED_ABIS:" + Arrays.toString(Build.SUPPORTED_ABIS);
        StringBuilder result = new StringBuilder();
        if (board.contains("x86")){
            result.append(board);
        } else if (brand.contains("generic")) {
            result.append(brand);
        } else if (abi.contains("x86")) {
            result.append(abi);
        } else if (device.contains("x86")||device.contains("generic")) {
            result.append(device);
        } else if (model.contains("Genymotion") || model.contains("x86")) {
            result.append(model);
        } else if (product.contains("sdk") || product.contains("x86")) {
            result.append(product);
        } else if (support.contains("x86") || !support.contains("arm")) {
            result.append(support);
        }
        return result.toString();
    }
    //检查硬件特征
    public String checkHardwareFeatures(Context context) {
        PackageManager pm = context.getPackageManager();
        boolean hasTelephony = pm.hasSystemFeature(PackageManager.FEATURE_TELEPHONY);
        boolean hasSensor = pm.hasSystemFeature(PackageManager.FEATURE_SENSOR_ACCELEROMETER);
        return "android. hardware. telephony:" + hasTelephony +"\n" +
               "android. hardware. sensor. accelerometer" + hasSensor; // 模拟器可能缺少这些特征
    }
    //检查文件系统
    public String checkFileSystem() {
        String[] emulatorFiles = {
                "/dev/socket/qemud",
                "/dev/qemu_pipe",
        };
        StringBuilder result = new StringBuilder();
        for (String filePath : emulatorFiles) {
            if (new File(filePath).exists()) {
                System.out.println(filePath);
                result.append(filePath);
            }
        }
        return result.toString(); // 没有找到模拟器特有文件
    }
    //检查运行程序
    public String checkRunningApps() {
        try {
            Process process = Runtime.getRuntime().exec("ps");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            StringBuilder result = new StringBuilder();
            while ((line = in.readLine()) != null) {
                System.out.println(line);
                if (line.contains("emulator")) {
                    result.append(line); // 找到模拟器相关进程
                }
            }
            return result.toString();
        } catch (IOException e) {
            System.out.println("f");
            return e.toString(); // 读取进程信息失败
        }
    }
    //检查电池状态
    public boolean checkBattery(Context context) {
        // 获取电池状态
        IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        Intent batteryStatus = context.registerReceiver(null, ifilter);
        if (batteryStatus != null) {
            int batteryLevel = batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
            int batteryScale = batteryStatus.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
            float batteryPct = batteryLevel * 100 / (float)batteryScale;
            System.out.println(batteryPct);
            boolean isCharging = batteryStatus.getIntExtra(BatteryManager.EXTRA_STATUS, -1) == BatteryManager.BATTERY_STATUS_CHARGING;
            // 判断电池电量和充电状态，通常模拟器电池满电且不在充电
            return batteryPct == 80.0 && !isCharging; // 可能在模拟器中
        }
        return false; // 不在模拟器中
    }
}
