package com.example.app1;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;

public class test {

    public String tf(){
        String t = "\n\ntest:";

        if(checkKernelLogsForMagisk())
            t += "\ncheckKernelLogsForMagisk";
        if(checkKernelModules())
            t += "\ncheckKernelModules";
        if(checkMagiskMountPoints())
            t += "\ncheckMagiskMountPoints";
        if(checkNetworkTraffic())
            t += "\ncheckNetworkTraffic";
        if(checkProcForMagisk())
            t += "\ncheckProcForMagisk";
        if(detectCodeInjection())
            t += "\ncheckKernelLogsForMagisk";
        if(detectMagiskFiles())
            t += "\ncheckKernelLogsForMagisk";
        if(detectHiddenProcesses())
            t += "\ncheckKernelLogsForMagisk";
        if(detectKernelModification())
            t += "\ncheckKernelLogsForMagisk";
        if(detectZygoteHooks())
            t += "\ncheckKernelLogsForMagisk";
        if(detectMagiskProperties())
            t += "\ncheckKernelLogsForMagisk";
        if(detectReflectionUsage())
            t += "\ncheckKernelLogsForMagisk";
        if(detectVirtualization())
            t += "\ncheckKernelLogsForMagisk";

        System.out.println(t);

        return t;
    }

    private boolean detectMagiskFiles() {
        String[] magiskPaths = {
                "/sbin/.magisk/",           // 通常是 Magisk 的主路径
                "/data/adb/magisk/",        // Magisk 安装的默认目录
                "/cache/.magisk/",          // 缓存目录中可能的痕迹
                "/system/.magisk/",         // 系统分区中的隐藏路径
                "/dev/.magisk_unblock/",    // 特殊的解锁路径
                "/dev/.magisk/",            // 用于 Magisk 管理的设备文件
                "/data/adb/magisk.db"       // 数据库文件
        };
        for (String path : magiskPaths) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }

    private boolean checkMagiskMountPoints() {
        try {
            Process process = Runtime.getRuntime().exec("mount");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {

                if (line.contains("/sbin") && line.contains("tmpfs")) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean detectZygoteHooks() {
        try {
            Process process = Runtime.getRuntime().exec("ps");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {
                if (line.contains("zygote") && line.contains("magisk")) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean detectMagiskProperties() {
        String[] properties = {
                "ro.magisk.hide",  // Magisk Hide 的标志属性
                "persist.magisk.hide",
                "ro.magisk.version",  // Magisk 版本号
                "ro.magisk.versionCode"
        };

        for (String prop : properties) {
            String value = getSystemProperty(prop);
            if (value != null && !value.isEmpty()) {
                return true;
            }
        }
        return false;
    }

    private String getSystemProperty(String propName) {
        try {
            Process process = Runtime.getRuntime().exec("getprop " + propName);
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            return in.readLine();
        } catch (Exception e) {
            return null;
        }
    }

    private boolean detectKernelModification() {
        try {
            Process process = Runtime.getRuntime().exec("dmesg | grep magisk");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {
                if (line.contains("magisk")) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkProcForMagisk() {
        try {
            Process process = Runtime.getRuntime().exec("cat /proc/self/mountinfo");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {
                if (line.contains("/sbin/.magisk")) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkKernelLogsForMagisk() {
        try {
            Process process = Runtime.getRuntime().exec("cat /dev/kmsg");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {
                if (line.contains("magisk")) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean detectCodeInjection() {
        try {
            // 检测应用程序是否被注入非法代码
            String[] suspiciousLibs = { "xposed", "substrate", "magisk" };
            for (String lib : suspiciousLibs) {
                if (isLibraryLoaded(lib)) {
                    return true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private boolean isLibraryLoaded(String libName) {
        try {
            Process process = Runtime.getRuntime().exec("cat /proc/self/maps");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {
                if (line.contains(libName)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean detectReflectionUsage() {
        try {
            Process process = Runtime.getRuntime().exec("ps -A | grep java");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {
                if (line.contains("Reflection")) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean detectHiddenProcesses() {
        try {
            Process process = Runtime.getRuntime().exec("ps | grep su");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {
                if (line.contains("su")) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkNetworkTraffic() {
        try {
            Process process = Runtime.getRuntime().exec("tcpdump -i any -vv");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {
                if (line.contains("magisk")) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean detectVirtualization() {
        try {
            Process process = Runtime.getRuntime().exec("lsmod | grep kvm");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {
                if (line.contains("kvm")) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean checkKernelModules() {
        try {
            Process process = Runtime.getRuntime().exec("lsmod");
            BufferedReader in = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;

            while ((line = in.readLine()) != null) {

                if (line.contains("magisk")) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }
}
