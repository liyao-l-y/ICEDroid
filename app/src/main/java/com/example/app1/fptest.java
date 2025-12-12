package com.example.app1;

import android.annotation.SuppressLint;
import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.media.RingtoneManager;
import android.net.Uri;
import android.os.BatteryManager;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;
import android.view.WindowManager;

import android.os.Bundle;
import android.os.Process;
import android.util.DisplayMetrics;
import android.view.Display;
import android.webkit.WebSettings;


import androidx.annotation.NonNull;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class fptest {
    public List<String> getProperties(Context context) {
        List<String> properties = new ArrayList<>();

        int availableCores = Runtime.getRuntime().availableProcessors();
        properties.add("可⽤处理器核⼼数:" + availableCores);
        properties.addAll(developmentSettings(context));
        properties.addAll(checkBattery(context));

        return getStrings(properties);
    }


    private List<String> developmentSettings(Context context){
        List<String> d = new ArrayList<>();

        int developmentSettings = Settings.Secure.getInt(context.getContentResolver(), Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0);
        if (developmentSettings == 1) {
            // 开发者选项已启⽤
            d.add("开发者选项:已启⽤");
        }else {
            d.add("开发者选项:未启⽤");
        }
        int adbEnabled = Settings.Global.getInt(context.getContentResolver(), Settings.Global.ADB_ENABLED, 0);
        if (adbEnabled == 1) {
            // USB调试已启⽤
            d.add("USB调试:已启⽤");
        }else {
            d.add("USB调试:未启⽤");
        }
        return getStrings(d);
    }

    private static @NonNull List<String> getStrings(List<String> properties) {
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

    private List<String> checkBattery(Context context) {
        List<String> b = new ArrayList<>();
        // 获取电池状态
        IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        Intent batteryStatus = context.registerReceiver(null, ifilter);
        if (batteryStatus != null) {
            int batteryLevel = batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1);
            int batteryScale = batteryStatus.getIntExtra(BatteryManager.EXTRA_SCALE, -1);
            //计算电量
            float batteryPct = batteryLevel * 100 / (float)batteryScale;
            b.add("当前电量:" + batteryPct);
            //是否充电
            boolean isCharging = batteryStatus.getIntExtra(BatteryManager.EXTRA_STATUS, -1) == BatteryManager.BATTERY_STATUS_CHARGING;
            //充电方式
            boolean usbCharge = batteryStatus.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) == BatteryManager.BATTERY_PLUGGED_USB;
            boolean acCharge = batteryStatus.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1) == BatteryManager.BATTERY_PLUGGED_AC;
            if (isCharging){
                if(usbCharge){
                    b.add("充电状态:正在使用usb充电");
                }
                if(acCharge){
                    b.add("充电状态:正在使用交流充电器充电");
                }
            }else {
                b.add("充电状态:未处于充电状态");
            }
        }
        return b;
    }

    @SuppressLint("DefaultLocale")
    public String getDisplayInformation(Context context) {
        StringBuilder info = new StringBuilder();

        // 正确获取WindowManager服务
        WindowManager windowManager = (WindowManager) context.getSystemService(Context.WINDOW_SERVICE);
        Display display = windowManager.getDefaultDisplay();

        // 获取显示器基本信息
        DisplayMetrics metrics = new DisplayMetrics();
        display.getMetrics(metrics);

        // 获取更精确的显示器物理尺寸
        DisplayMetrics realMetrics = new DisplayMetrics();
        display.getRealMetrics(realMetrics);

        // 分辨率信息
        info.append("分辨率: ").append(realMetrics.widthPixels).append(" x ").append(realMetrics.heightPixels).append(" 像素\n");

        // 显示密度信息
        info.append("屏幕密度: ").append(metrics.density).append("\n");
        info.append("点密度: ").append(metrics.densityDpi).append(" dpi\n");
        info.append("缩放密度: ").append(metrics.scaledDensity).append("\n");

        // 刷新率信息
        float refreshRate = display.getRefreshRate();
        info.append("刷新率: ").append(refreshRate).append(" Hz\n");

        // 对于Android 11及以上版本，可以获取支持的刷新率范围
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                Display.Mode[] modes = display.getSupportedModes();
                info.append("支持的刷新率: ");
                for (Display.Mode mode : modes) {
                    info.append(mode.getRefreshRate()).append(" Hz, ");
                }
                info.append("\n");
            } catch (Exception e) {
                info.append("无法获取支持的刷新率模式\n");
            }
        }

        // 获取屏幕物理尺寸（英寸）
        double x = Math.pow(realMetrics.widthPixels / realMetrics.xdpi, 2);
        double y = Math.pow(realMetrics.heightPixels / realMetrics.ydpi, 2);
        double screenInches = Math.sqrt(x + y);
        info.append("屏幕物理尺寸: ").append(String.format("%.2f", screenInches)).append(" 英寸\n");

        System.out.println(info);
        return info.toString();
    }

    public String isMonkey(){
        if(ActivityManager.isUserAMonkey()) {
            return "isUserAMonkey：monkey";
        }
        return "isUserAMonkey：user";
    }

    @SuppressLint("ObsoleteSdkInt")
    public  String getUserAgent(Context context) {
        String userAgent = null;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR1) {
            try {
                userAgent = WebSettings.getDefaultUserAgent(context);
            } catch (Throwable ignored) {
            }
            if (userAgent == null) {
                userAgent = System.getProperty("http.agent");
            }
        } else {
            userAgent = System.getProperty("http.agent");
        }
        StringBuilder sb = new StringBuilder();
        if (userAgent != null) {
            for (int i = 0, length = userAgent.length(); i < length; i++) {
                char c = userAgent.charAt(i);
                if (c <= '\u001f' || c >= '\u007f') {
                    sb.append(String.format("\\u%04x", (int) c));
                } else {
                    sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    public String getDefaultRingtoneInfo(Context context) {
        StringBuilder info = new StringBuilder();

        try {
            // 获取默认电话铃声
            Uri defaultRingtoneUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_RINGTONE);
            info.append("默认电话铃声 URI: ").append(defaultRingtoneUri.toString()).append("\n");

            // 获取默认通知铃声
            Uri defaultNotificationUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_NOTIFICATION);
            info.append("默认通知铃声 URI: ").append(defaultNotificationUri.toString()).append("\n");

            // 获取默认闹钟铃声
            Uri defaultAlarmUri = RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM);
            info.append("默认闹钟铃声 URI: ").append(defaultAlarmUri.toString()).append("\n");

            // 尝试获取铃声的标题
            android.media.Ringtone ringtone = RingtoneManager.getRingtone(context, defaultRingtoneUri);
            String ringtoneName = ringtone.getTitle(context);
            info.append("默认电话铃声名称: ").append(ringtoneName).append("\n");

            // 获取所有可用铃声列表
            info.append("系统所有可用铃声列表:\n");
            RingtoneManager manager = new RingtoneManager(context);

            // 设置要查询的铃声类型（电话铃声、通知铃声和闹钟铃声）
            manager.setType(RingtoneManager.TYPE_RINGTONE |
                    RingtoneManager.TYPE_NOTIFICATION |
                    RingtoneManager.TYPE_ALARM);

            android.database.Cursor cursor = manager.getCursor();
            int count = cursor.getCount();
            info.append("总铃声数: ").append(count).append("\n");
            /*
            // 列出前10个铃声（避免列表过长）
            int limit = Math.min(10, count);
            for (int i = 0; i < limit; i++) {
                cursor.moveToPosition(i);
                String title = manager.getRingtone(i).getTitle(context);
                Uri ringtoneUri = manager.getRingtoneUri(i);
                info.append(i + 1).append(". ").append(title).append("\n")
                        .append("   URI: ").append(ringtoneUri.toString()).append("\n\n");
            }

            if (count > 10) {
                info.append("... 以及其他 ").append(count - 10).append(" 个铃声\n");
            }

             */

        } catch (Exception e) {
            info.append("获取铃声信息时出错: ").append(e.getMessage());
            e.printStackTrace();
        }

        return info.toString();
    }

    public String getAppInfo(Context context) {
        StringBuilder info = new StringBuilder();
        try {
            // 获取应用包名
            String packageName = context.getPackageName();
            info.append("包名 (Package Name): ").append(packageName).append("\n");
            // 获取应用版本信息
            try {
                PackageInfo packageInfo = context.getPackageManager().getPackageInfo(packageName, 0);
                info.append("版本名称 (Version Name): ").append(packageInfo.versionName).append("\n");
                info.append("版本代码 (Version Code): ").append(packageInfo.versionCode).append("\n");
            } catch (PackageManager.NameNotFoundException e) {
                info.append("无法获取版本信息: ").append(e.getMessage()).append("\n");
            }
            // 获取当前进程ID (PID)
            int pid = Process.myPid();
            info.append("进程ID (PID): ").append(pid).append("\n");
            // 获取用户ID (UID)
            int uid = Process.myUid();
            info.append("用户ID (UID): ").append(uid).append("\n");
            // 获取进程名称
            String processName = getProcessName(context, pid);
            if (processName != null) {
                info.append("进程名称 (Process Name): ").append(processName).append("\n");
            }
            // 获取组ID (GID)
            int[] gids = getGroupIds();
            if (gids != null && gids.length > 0) {
                info.append("组ID (GIDs): ");
                for (int gid : gids) {
                    info.append(gid).append(" ");
                }
                info.append("\n\n");
            } else {
                info.append("无法获取组ID (GIDs)\n");
            }
            // 获取当前进程的线程信息
            int threadId = Process.myTid();
            info.append("主线程ID (Main Thread ID): ").append(threadId).append("\n");
            // 尝试获取进程状态信息
            info.append("进程状态信息:\n");
            info.append(getProcessStatusInfo(pid));
        } catch (Exception e) {
            info.append("获取应用信息时出现错误: ").append(e.getMessage());
            e.printStackTrace();
        }
        return info.toString();
    }
    // 获取进程名称的方法
    private String getProcessName(Context context, int pid) {
        // 方法1：通过ActivityManager获取
        ActivityManager am = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        List<ActivityManager.RunningAppProcessInfo> runningProcesses = am.getRunningAppProcesses();
        if (runningProcesses != null) {
            for (ActivityManager.RunningAppProcessInfo processInfo : runningProcesses) {
                if (processInfo.pid == pid) {
                    return processInfo.processName;
                }
            }
        }
        // 方法2：通过读取/proc/[pid]/cmdline文件获取
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/" + pid + "/cmdline"));
            String processName = reader.readLine();
            reader.close();
            if (processName != null) {
                processName = processName.trim();
                if (!processName.isEmpty()) {
                    return processName;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }
    // 获取组ID的方法
    private int[] getGroupIds() {
        try {
            Class<?> processClass = Class.forName("android.os.Process");
            java.lang.reflect.Method method;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                // Android 10+ 尝试反射获取隐藏方法
                method = processClass.getDeclaredMethod("getProcessGids");
            } else {
                // 老版本 Android 尝试 getGroups 方法
                method = processClass.getDeclaredMethod("getGroups");
            }
            method.setAccessible(true);
            return (int[]) method.invoke(null);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    // 获取进程状态详细信息
    private String getProcessStatusInfo(int pid) {
        StringBuilder statusInfo = new StringBuilder();
        try {
            BufferedReader reader = new BufferedReader(new FileReader("/proc/" + pid + "/status"));
            String line;
            while ((line = reader.readLine()) != null) {
                statusInfo.append(line).append("\n");
            }
            reader.close();
        } catch (IOException e) {
            statusInfo.append("无法读取进程状态信息: ").append(e.getMessage());
            e.printStackTrace();
        }
        return statusInfo.toString();
    }
}
