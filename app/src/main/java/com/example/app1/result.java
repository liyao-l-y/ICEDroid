package com.example.app1;

import android.content.Context;
import android.os.Build;

import androidx.annotation.NonNull;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

public class result {
    //-----------------------------------------------ROOT检测------------------------------------------------------
    public JSONObject rootCheck() throws IOException, JSONException {
        rootcheck rc = new rootcheck();
        JSONObject rootCheckResult = new JSONObject();

        // 检查SU命令
        String suCommandResult = rc.checkSuCommand();
        JSONObject suCommandObj = new JSONObject();
        suCommandObj.put("purpose", "检测设备是否具有超级用户(root)权限");
        suCommandObj.put("method", "尝试执行'which su'命令，检查su工具是否存在并可执行");
        suCommandObj.put("data", suCommandResult);
        rootCheckResult.put("检查SU命令", suCommandObj);

        // 检查root文件
        String rootFilesResult = rc.checkRootFiles();
        JSONObject rootFilesObj = new JSONObject();
        rootFilesObj.put("purpose", "检测设备上是否存在常见的root相关文件");
        rootFilesObj.put("method", "检查常见root文件路径如/system/xbin/su、/magisk等是否存在");
        String[] Lines = rootFilesResult.split("\n");
        JSONObject rootFiles = new JSONObject();
        for (int i = 1; i < Lines.length; i++) {
            String line = Lines[i];
            if (line.contains(":")) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    String property = parts[0].trim();
                    String value = parts[1].trim();
                    rootFiles.put(property, value);
                }
            }
        }
        rootFilesObj.put("data", rootFiles);
        rootCheckResult.put("检查root文件", rootFilesObj);

        // 检查系统标签
        String systemTagsResult = rc.checkSystemTags();
        JSONObject systemTagsObj = new JSONObject();
        systemTagsObj.put("purpose", "检测系统ROM签名是否为开发版或测试版");
        systemTagsObj.put("method", "检查Build.TAGS是否不等于'release-keys'，非正式发布的ROM通常带有test-keys标签");
        systemTagsObj.put("data", systemTagsResult);
        rootCheckResult.put("检查系统标签", systemTagsObj);

        // 检查系统分区
        String mountInfoResult = rc.checkMountInfo();
        JSONObject mountInfoObj = new JSONObject();
        mountInfoObj.put("purpose", "检测系统分区是否被挂载为可读写模式");
        mountInfoObj.put("method", "执行'mount'命令检查系统分区挂载参数，正常情况下系统分区应该是只读的");
        mountInfoObj.put("data", mountInfoResult);
        rootCheckResult.put("检查分区读写模式", mountInfoObj);

        // 检查系统属性
        String systemPropertyResult = rc.checkSystemProperty();
        JSONObject systemPropertyObj = new JSONObject();
        systemPropertyObj.put("purpose", "检测系统调试和安全相关属性是否异常");
        systemPropertyObj.put("method", "检查ro.debuggable和ro.secure属性值，正常设备中ro.debuggable应为0，ro.secure应为1");
        systemPropertyObj.put("data", systemPropertyResult);
        rootCheckResult.put("检查系统属性", systemPropertyObj);

        // 检查SELinux
        String selinuxStatus = rc.getSELinuxStatus();
        JSONObject selinuxObj = new JSONObject();
        selinuxObj.put("purpose", "检测SELinux安全策略是否处于正常强制模式");
        selinuxObj.put("method", "执行'getenforce'命令检查SELinux状态，正常应为enforcing模式");
        selinuxObj.put("data", selinuxStatus);
        rootCheckResult.put("检查SELinux状态", selinuxObj);

        // 检查bootloader
        String bootloaderResult = rc.isBootloaderLocked();
        JSONObject bootloaderObj = new JSONObject();
        bootloaderObj.put("purpose", "检测设备的Bootloader是否处于锁定状态");
        bootloaderObj.put("method", "检查ro.boot.verifiedbootstate属性和硬件密钥认证状态，正常设备应为锁定状态");
        bootloaderObj.put("data", bootloaderResult);
        rootCheckResult.put("检查Bootloader状态", bootloaderObj);

        // 检查TEE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            String teeResult = rc.checkTEE();
            JSONObject teeObj = new JSONObject();
            teeObj.put("purpose", "检测设备是否使用可信执行环境(TEE)保护密钥");
            teeObj.put("method", "通过Android Keystore生成密钥并检查是否存储在安全硬件中");
            teeObj.put("data", teeResult);
            rootCheckResult.put("检查TEE状态", teeObj);
        }

        return rootCheckResult;
    }



    //-----------------------------------------------模拟器检测------------------------------------------------------
    public JSONObject emulatorCheck(Context context) throws JSONException {
        emulatorcheck ec = new emulatorcheck();
        fingerprintjni fj = new fingerprintjni();

        JSONObject resultJson = new JSONObject();

        // 检查设备指纹
        JSONObject fingerprintObj = new JSONObject();
        fingerprintObj.put("purpose", "检测设备指纹是否包含模拟器特征");
        fingerprintObj.put("method", "检查系统属性中是否包含x86等模拟器相关标识");
        fingerprintObj.put("data", ec.checkfingerprint());
        resultJson.put("检查设备指纹", fingerprintObj);

        // 检查设备属性
        JSONObject buildObj = new JSONObject();
        buildObj.put("purpose", "检测设备Build属性是否具有模拟器特征");
        buildObj.put("method", "分析设备BOARD、BRAND、CPU_ABI等Build属性是否包含generic、x86等模拟器标识");
        buildObj.put("data", ec.checkBuild());
        resultJson.put("检查设备属性", buildObj);

        // 检查硬件特征
        JSONObject hardwareObj = new JSONObject();
        hardwareObj.put("purpose", "检测设备硬件特征是否符合真实设备特征");
        hardwareObj.put("method", "检查设备是否具备电话功能和加速度传感器等真实设备常见特征");
        hardwareObj.put("data", ec.checkHardwareFeatures(context));
        resultJson.put("检查硬件特征", hardwareObj);

        // 检查文件系统
        JSONObject fileSystemObj = new JSONObject();
        fileSystemObj.put("purpose", "检测设备文件系统中是否存在模拟器特有文件");
        fileSystemObj.put("method", "检查/dev/socket/qemud、/dev/qemu_pipe等模拟器特有文件是否存在");
        fileSystemObj.put("data", ec.checkFileSystem());
        resultJson.put("检查文件系统", fileSystemObj);

        // 检查运行程序
        JSONObject runningAppsObj = new JSONObject();
        runningAppsObj.put("purpose", "检测设备中是否运行着模拟器相关进程");
        runningAppsObj.put("method", "通过ps命令查看运行进程列表，检查是否存在emulator等关键字");
        runningAppsObj.put("data", ec.checkRunningApps());
        resultJson.put("检查运行程序", runningAppsObj);

        // 检查电池状态
        JSONObject batteryObj = new JSONObject();
        batteryObj.put("purpose", "检测设备电池状态是否符合真实设备特征");
        batteryObj.put("method", "分析电池电量和充电状态，模拟器通常显示固定电量(80%)且不在充电");
        batteryObj.put("data", ec.checkBattery(context) ? "电池状态可能存在异常" : "电池状态正常");
        resultJson.put("检查电池状态", batteryObj);

        // 检查子进程退出状态
        JSONObject qemuBkptObj = new JSONObject();
        qemuBkptObj.put("purpose", "通过断点指令检测QEMU虚拟执行环境");
        qemuBkptObj.put("method", "在子进程中执行断点指令并分析进程行为，真实设备和模拟器对断点指令处理方式不同");
        qemuBkptObj.put("data", fj.qemubkpt());
        resultJson.put("检查子进程退出状态", qemuBkptObj);

        // 检查指令执行速度
        JSONObject executeSpeedObj = new JSONObject();
        executeSpeedObj.put("purpose", "分析指令执行时间分布检测模拟环境");
        executeSpeedObj.put("method", "使用多线程测量指令执行时间分布特征，模拟器通常会产生特定的执行延迟模式");
        executeSpeedObj.put("data", fj.executespeed());
        resultJson.put("检查指令执行速度", executeSpeedObj);

        return resultJson;
    }



    //-----------------------------------------------hook检测方法------------------------------------------------------
    public JSONObject checkhook() throws JSONException {
        hookcheck hc = new hookcheck();
        fingerprintjni j = new fingerprintjni();
        // 构建JSON对象
        JSONObject jsonResult = new JSONObject();

        // Java层Frida检测
        JSONObject fridaCheck = new JSONObject();
        fridaCheck.put("purpose", "检测设备上是否存在Frida框架");
        fridaCheck.put("method", "分析内存映射文件和网络端口，查找Frida特征");
        fridaCheck.put("data", hc.checkfrida());
        jsonResult.put("Java层Frida检测", fridaCheck);

        // Java层Xposed检测
        JSONObject xposedCheck = new JSONObject();
        xposedCheck.put("purpose", "检测设备上是否安装了Xposed框架");
        xposedCheck.put("method", "检查内存映射和Xposed安装目录是否存在");
        xposedCheck.put("data", hc.checkxposed());
        jsonResult.put("Java层Xposed检测", xposedCheck);

        // Native层Frida端口检测
        JSONObject portCheck = new JSONObject();
        portCheck.put("purpose", "检测Frida服务器端口是否开放");
        portCheck.put("method", "尝试连接Frida服务器常用端口并发送AUTH请求，分析响应");
        portCheck.put("data", j.check());
        jsonResult.put("Native层Frida端口检测", portCheck);

        // Native层内存映射检测
        JSONObject mapsCheck = new JSONObject();
        mapsCheck.put("purpose", "检测进程内存映射中是否存在Hook框架");
        mapsCheck.put("method", "分析/proc/self/maps文件，查找frida、gadget、xposed等特征字符串");
        mapsCheck.put("data", j.mapscheck());
        jsonResult.put("Native层内存映射检测", mapsCheck);

        // Native层父进程检测
        JSONObject parentsCheck = new JSONObject();
        parentsCheck.put("purpose", "检测父进程是否为正常的zygote进程");
        parentsCheck.put("method", "读取父进程的cmdline，检查是否为正常的Android进程启动链");
        parentsCheck.put("data", j.parentscheck());
        jsonResult.put("Native层父进程检测", parentsCheck);

        // Native层跟踪进程检测
        JSONObject courseCheck = new JSONObject();
        courseCheck.put("purpose", "检测是否存在跟踪当前进程的调试器");
        courseCheck.put("method", "检查进程状态文件中是否存在frida或xposed特征，并尝试终止可疑跟踪进程");
        courseCheck.put("data", j.coursecheck());
        jsonResult.put("Native层跟踪进程检测", courseCheck);

        return jsonResult;
    }

    //-----------------------------------------------设备指纹检测------------------------------------------------------
    public JSONObject checkFingerPrint(Context context) throws JSONException {
        fingerprint fp = new fingerprint();
        fingerprintjni j = new fingerprintjni();

        JSONObject jsonResult = new JSONObject();

        // Java层设备ID检测
        String deviceID = fp.getDeviceID(context.getContentResolver());
        JSONObject javaDeviceID = new JSONObject();
        javaDeviceID.put("purpose", "获取设备的唯一标识符");
        javaDeviceID.put("method", "通过Settings.Secure获取Android ID等设备唯一标识信息");
        javaDeviceID.put("data", deviceID.replace("设备指纹：\n", "").trim());
        jsonResult.put("Java层设备ID检测", javaDeviceID);

        // Java层网络地址检测
        String networkAddress = fp.getLocalMacAddress();
        JSONObject javaNetworkAddress = new JSONObject();
        javaNetworkAddress.put("purpose", "获取设备的网络地址信息");
        javaNetworkAddress.put("method", "获取设备的IP地址和MAC地址等网络标识信息");
        javaNetworkAddress.put("data", networkAddress.replace("网络地址：\n", "").trim());
        jsonResult.put("Java层网络地址检测", javaNetworkAddress);

        // Java层系统属性检测
        String systemProperties = fp.getSystemProperties();
        JSONObject javaSystemProperties = new JSONObject();
        javaSystemProperties.put("purpose", "获取设备的系统属性信息");
        javaSystemProperties.put("method", "通过SystemProperties和Build类获取设备详细的系统信息和指纹");

        String[] javaLines = systemProperties.replace("系统指纹：\n", "").split("\n");
        JSONObject javaProperties = new JSONObject();
        for (int i = 1; i < javaLines.length; i++) {
            String line = javaLines[i];
            if (line.contains(":")) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    String property = parts[0].trim();
                    String value = parts[1].trim();
                    javaProperties.put(property, value);
                }
            }
        }
        javaSystemProperties.put("data", systemProperties.replace("系统指纹：\n", "").trim());

        jsonResult.put("Java层系统属性检测", javaProperties);

        // Native层Android ID检测
        String androidID = j.getandroidid();
        JSONObject nativeAndroidID = new JSONObject();
        nativeAndroidID.put("purpose", "通过Native层获取设备的Android ID等设备唯一标识信息");
        nativeAndroidID.put("method", "通过JNI调用ContentResolver和Settings.Secure获取Android ID");
        nativeAndroidID.put("data", androidID);
        jsonResult.put("Native层设备ID检测", nativeAndroidID);

        // Native层网络地址检测
        String netfp = j.netfp();
        JSONObject nativeNetworkAddress = new JSONObject();
        nativeNetworkAddress.put("purpose", "通过Native层获取设备的网络地址信息");
        nativeNetworkAddress.put("method", "使用JNI调用WifiManager和DhcpInfo获取IP地址和MAC地址");
        nativeNetworkAddress.put("data", netfp);
        jsonResult.put("Native层网络地址检测", nativeNetworkAddress);

        // Native层系统指纹检测
        String fingerprint = j.fingerprint();
        JSONObject nativeFingerprint = new JSONObject();
        nativeFingerprint.put("purpose", "通过Native层获取完整的系统指纹信息");
        nativeFingerprint.put("method", "使用__system_property_get函数获取系统属性，构建完整的设备指纹");

        String[] nativeLines = fingerprint.split("\n");
        JSONObject nativeProperties = new JSONObject();
        for (int i = 1; i < nativeLines.length; i++) {
            String line = nativeLines[i];
            if (line.contains(":")) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    String property = parts[0].trim();
                    String value = parts[1].trim();
                    nativeProperties.put(property, value);
                }
            }
        }
        nativeFingerprint.put("data", nativeProperties);

        jsonResult.put("Native层系统指纹检测", nativeFingerprint);

        // 对比结果
        String comparison = compareResults(systemProperties, "系统指纹：" + fingerprint + "\n");
        JSONObject comparisonResult = new JSONObject();
        comparisonResult.put("purpose", "比较Java层和Native层获取的系统指纹是否一致");
        comparisonResult.put("method", "逐项比较Java层和Native层获取的系统属性值，检查是否存在差异");

        String[] Lines = comparison.split("\n");
        JSONObject compareProperties = new JSONObject();
        for (int i = 1; i < Lines.length; i++) {
            String line = Lines[i];
            if (line.contains(":")) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    String property = parts[0].trim();
                    String value = parts[1].trim();
                    compareProperties.put(property, value);
                }
            }
        }
        comparisonResult.put("data", compareProperties);

        jsonResult.put("指纹对比结果", comparisonResult);

        return jsonResult;
    }



    private String compareResults(String result1, String result2) {
        StringBuilder s = new StringBuilder();
        String[] lines1 = result1.split("\n");
        String[] lines2 = result2.split("\n");
        StringBuilder result = getStringBuilder(lines1, lines2);
        String[] fingerprint = new String[14];
        System.arraycopy(lines1,2,fingerprint,0,6);
        System.arraycopy(lines2,2,fingerprint,6,6);
        System.arraycopy(lines1,lines1.length-1,fingerprint,12,1);
        System.arraycopy(lines2,lines2.length-1,fingerprint,13,1);
        System.out.println(Arrays.toString(fingerprint));
        if(areValuesIdentical(fingerprint))
            s.append("\n指纹属性一致\n");
        s.append(result);
        return s.toString();
    }

    private @NonNull StringBuilder getStringBuilder(String[] lines1, String[] lines2) {
        StringBuilder result = new StringBuilder();
        //找到最大的行数
        int maxLines = Math.max(lines1.length, lines2.length);
        for (int i = 0; i < maxLines; i++) {
            String line1 = i < lines1.length ? lines1[i] : "无结果";  // 如果行不存在，则显示“无结果”
            String line2 = i < lines2.length ? lines2[i] : "无结果";  // 如果行不存在，则显示“无结果”
            String[] parts1 = line1.split(":", 2);
            String[] parts2 = line2.split(":", 2);
            //默认值
            String key1 = parts1.length > 0 ? parts1[0].trim() : "无结果";
            String value1 = parts1.length > 1 ? parts1[1].trim() : "无结果";
            String value2 = parts2.length > 1 ? parts2[1].trim() : "无结果";
            //对比结果
            if(!value1.equals(value2)){
                String r = key1 + ":" + value1 + "(java层)" + "\\" + value2 + "(native层)" + "\n";
                result.append(r);
            }
        }
        return result;
    }

    private boolean areValuesIdentical(String[] data) {
        Set<String> valuesSet = new HashSet<>();
        for (String entry : data) {
            // 将字符串按冒号分割，确保有两个部分
            String[] parts = entry.split(":", 2);
            // 如果分割成功，添加冒号后的值到集合中
            if (parts.length == 2) {
                String value = parts[1].trim(); // 获取冒号后的值并去除空白
                valuesSet.add(value);
            } else {
                // 如果没有冒号或格式不正确，可以选择抛出异常或添加默认值
                // 这里直接返回 false 表示数据格式不符合要求
                return false;
            }
        }
        // 如果集合的大小为 1，表示所有值相同
        return valuesSet.size() == 1;
    }

    //-----------------------------------------------native检测方法------------------------------------------------------
    public String fingerprintjni(){
        fingerprintjni j = new fingerprintjni();

        StringBuilder s = new StringBuilder("★native层检测★");
        String fingerprint = "\n系统指纹：" + j.fingerprint() + "\n";
        String netaddress = "\n网络地址：\n" + j.netfp() + "\n";
        String hookcheck = "\nhook检测：\n" + j.check() + "\n" + j.mapscheck() + "\n";
        String appnames = "\n检测已安装应用：\n" + j.getappnames() + "\n";
        String cert = "\n检测CA证书：\n" + j.getcertificate() + "\n";
        String features = "\n检测支持软硬件：\n" + j.getdevicefeatures() + "\n";
        s.append(fingerprint).append(netaddress).append(hookcheck).append(appnames).append(cert).append(features).append("\n");

        return s.toString();
    }

    //------------------------------------------测试-------------------------------------------------------------------
    public JSONObject test(Context context) throws JSONException {
        fptest fp = new fptest();
        location lc = new location();

        JSONObject resultJson = new JSONObject();

        // 处理设备属性
        List<String> properties = fp.getProperties(context);
        JSONObject propertyObj = new JSONObject();
        propertyObj.put("purpose", "获取设备基本属性信息");
        propertyObj.put("method", "通过系统API获取设备的处理器核心数、开发者选项状态、USB调试状态、电池信息等");
        JSONObject propertydata = new JSONObject();
        for (String property : properties) {
            String[] parts = property.split(":", 2);
            System.out.println(parts);
            if (parts.length == 2) {
                String key = parts[0].trim();
                String value = parts[1].trim();
                try {
                    propertydata.put(key ,value);
                } catch (JSONException e) {
                    e.printStackTrace();
                }
            }
        }
        propertyObj.put("data", propertydata);
        resultJson.put("设备基本信息", propertyObj);
        System.out.println(resultJson);
        // 处理显示信息
        try {
            String displayInfo = fp.getDisplayInformation(context);
            JSONObject displayObj = new JSONObject();
            displayObj.put("purpose", "获取设备显示器详细信息");
            displayObj.put("method", "通过DisplayMetrics和WindowManager API获取分辨率、密度、刷新率等显示器参数");

            String[] Lines = displayInfo.split("\n");
            JSONObject d = new JSONObject();
            for (int i = 1; i < Lines.length; i++) {
                String line = Lines[i];
                if (line.contains(":")) {
                    String[] parts = line.split(":", 2);
                    if (parts.length == 2) {
                        String property = parts[0].trim();
                        String value = parts[1].trim();
                        d.put(property, value);
                    }
                }
            }
            displayObj.put("data", d);

            resultJson.put("显示信息", displayObj);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        System.out.println(resultJson);
        // 处理Monkey测试检测
        try {
            String monkeyStatus = fp.isMonkey();
            JSONObject monkeyObj = new JSONObject();
            monkeyObj.put("purpose", "检测应用是否在自动化测试环境中运行");
            monkeyObj.put("method", "使用ActivityManager.isUserAMonkey()方法检测是否由Monkey测试工具操作");
            monkeyObj.put("data", monkeyStatus.replace("isUserAMonkey：", ""));
            resultJson.put("Monkey测试检测", monkeyObj);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        // 处理UserAgent
        try {
            String userAgent = fp.getUserAgent(context);
            JSONObject uaObj = new JSONObject();
            uaObj.put("purpose", "获取设备浏览器用户代理字符串");
            uaObj.put("method", "通过WebSettings.getDefaultUserAgent或系统属性http.agent获取");
            uaObj.put("data", userAgent);
            resultJson.put("UserAgent", uaObj);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        // 处理铃声信息
        try {
            String ringtoneInfo = fp.getDefaultRingtoneInfo(context);
            JSONObject ringtoneObj = new JSONObject();
            ringtoneObj.put("purpose", "获取设备默认铃声和通知音配置");
            ringtoneObj.put("method", "通过RingtoneManager获取系统默认电话铃声、通知铃声和闹钟铃声");
            ringtoneObj.put("data", ringtoneInfo);
            resultJson.put("铃声信息", ringtoneObj);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        // 处理应用信息
        try {
            String appInfo = fp.getAppInfo(context);
            JSONObject appObj = new JSONObject();
            appObj.put("purpose", "获取当前应用的详细信息");
            appObj.put("method", "通过PackageManager和Process类获取应用包名、版本、进程ID等信息");

            String[] Lines = appInfo.split("\n");
            JSONObject a = new JSONObject();
            for (int i = 1; i < Lines.length; i++) {
                String line = Lines[i];
                if (line.contains(":")) {
                    String[] parts = line.split(":", 2);
                    if (parts.length == 2) {
                        String property = parts[0].trim();
                        String value = parts[1].trim();
                        a.put(property, value);
                    }
                }
            }
            appObj.put("data", a);

            resultJson.put("应用信息", appObj);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        // 处理位置信息
        try {
            String locationInfo = lc.getProvince(context);
            JSONObject locationObj = new JSONObject();
            locationObj.put("purpose", "获取设备所在地理位置");
            locationObj.put("method", "通过位置服务API获取设备当前位置信息");
            locationObj.put("data", locationInfo);
            resultJson.put("位置信息", locationObj);
        } catch (JSONException e) {
            e.printStackTrace();
        }

        return resultJson;
    }


    //------------------------------------------获取已安装应用----------------------------------------------------------
    public JSONObject appname(Context context) throws JSONException {
        appname an = new appname();
        fingerprintjni j = new fingerprintjni();

        JSONObject resultJson = new JSONObject();

        // 处理Java层获取的应用信息
        String javaan = an.getAllAppNames(context);
        String[] javaLines = javaan.split("\n");

        // 1. Java应用总数
        if (javaLines.length > 0 && javaLines[0].contains("应用的总个数")) {
            String[] parts = javaLines[0].split(":", 2);
            if (parts.length == 2) {
                JSONObject countJson = new JSONObject();
                countJson.put("purpose", "统计设备上安装的应用数量");
                countJson.put("method", "通过Java层PackageManager.getInstalledPackages获取应用列表并计数");
                countJson.put("data", parts[1].trim());

                resultJson.put("应用总数(Java层检测)", countJson);
            }
        }

        // 2. Java应用详细列表 - 将所有应用放在一个JSON对象中
        JSONObject javaAppsData = new JSONObject();
        for (int i = 1; i < javaLines.length; i++) {
            String line = javaLines[i];
            if (line.contains(":")) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    String appName = parts[0].trim();
                    String packageName = parts[1].trim();
                    javaAppsData.put(appName, packageName);
                }
            }
        }

        JSONObject javaAppsJson = new JSONObject();
        javaAppsJson.put("purpose", "获取设备上安装的应用信息");
        javaAppsJson.put("method", "通过Java层PackageManager获取应用名称和包名");
        javaAppsJson.put("data", javaAppsData);
        resultJson.put("应用列表(Java层检测)", javaAppsJson);

        // 处理Native层获取的应用信息
        String nativean = j.getappnames();
        String[] nativeLines = nativean.split("\n");

        // 3. Native应用总数
        if (nativeLines.length > 0 && nativeLines[0].contains("已安装应用个数")) {
            String[] parts = nativeLines[0].split(":", 2);
            if (parts.length == 2) {
                JSONObject countJson = new JSONObject();
                countJson.put("purpose", "统计设备上安装的应用数量");
                countJson.put("method", "通过Native层JNI调用PackageManager获取应用列表并计数");
                countJson.put("data", parts[1].trim());

                resultJson.put("应用总数(Native层检测)", countJson);
            }
        }

        // 4. Native应用详细列表 - 将所有应用放在一个JSON对象中
        JSONObject nativeAppsData = new JSONObject();
        for (int i = 1; i < nativeLines.length; i++) {
            String line = nativeLines[i];
            if (line.contains(":")) {
                String[] parts = line.split(":", 2);
                if (parts.length == 2) {
                    String appName = parts[0].trim();
                    String packageName = parts[1].trim();
                    nativeAppsData.put(appName, packageName);
                }
            }
        }

        JSONObject nativeAppsJson = new JSONObject();
        nativeAppsJson.put("purpose", "获取设备上安装的应用信息");
        nativeAppsJson.put("method", "通过Native层JNI调用PackageManager获取应用名称和包名");
        nativeAppsJson.put("data", nativeAppsData);
        resultJson.put("应用列表(Native层检测)", nativeAppsJson);

        return resultJson;
    }

    //------------------------------------------获取系统证书----------------------------------------------------------
    public JSONObject certinfo() throws JSONException {
        certificate c = new certificate();
        fingerprintjni j = new fingerprintjni();
        JSONObject resultJson = new JSONObject();
        // Java层检测
        String javaCerts = c.listInstalledCertificates();
        JSONObject javaObj = new JSONObject();
        javaObj.put("purpose", "获取设备上安装的信任证书列表");
        javaObj.put("method", "通过KeyStore.getInstance(\"AndroidCAStore\")获取系统证书存储");
        javaObj.put("data", javaCerts);
        resultJson.put("Java证书信息", javaObj);

        // Native层检测
        String nativeCerts = j.getcertificate();
        JSONObject nativeObj = new JSONObject();
        nativeObj.put("purpose", "通过Native层获取设备上安装的信任证书列表");
        nativeObj.put("method", "使用JNI调用KeyStore获取系统证书存储");
        nativeObj.put("data", nativeCerts);
        resultJson.put("Native证书信息", nativeObj);

        return resultJson;
    }



    //------------------------------------------获取支持软硬件----------------------------------------------------------
    public JSONObject devicefeatures(Context context) throws JSONException {
        devicesfeatures df = new devicesfeatures();
        fingerprintjni j = new fingerprintjni();

        JSONObject jsonOutput = new JSONObject();

        // Java层检测
        String javaResult = df.features(context);
        JSONObject javaObj = new JSONObject();
        javaObj.put("purpose", "获取设备支持的硬件和软件特性");
        javaObj.put("method", "通过PackageManager查询系统可用的FeatureInfo");
        javaObj.put("data", jsonEscape(javaResult));
        jsonOutput.put("设备功能(Java)", javaObj);

        // Native层检测
        String nativeResult = j.getdevicefeatures();
        JSONObject nativeObj = new JSONObject();
        nativeObj.put("purpose", "通过Native层获取设备支持的功能");
        nativeObj.put("method", "使用JNI调用PackageManager获取系统可用特性");
        nativeObj.put("data", jsonEscape(nativeResult));
        jsonOutput.put("设备功能(Native)", nativeObj);


        return jsonOutput;
    }

    //------------------------------------------密钥认证----------------------------------------------------------
    public JSONObject keyattestion() throws JSONException {
        keyattestion ka = new keyattestion();
        String certChainResult = ka.checkcertchain();

        // 创建主JSONObject
        JSONObject mainJson = new JSONObject();

        // 创建证书链信息对象
        JSONObject certChainInfo = new JSONObject();
        certChainInfo.put("purpose", "获取设备密钥证书链");
        certChainInfo.put("method", "从Android Keystore获取EC密钥的证书链");

        // 提取证书链部分
        int certChainStart = certChainResult.indexOf("证书链");
        int certChainEnd = certChainResult.indexOf("\n\n", certChainStart);
        if (certChainStart >= 0 && certChainEnd >= 0) {
            String certChain = certChainResult.substring(certChainStart, certChainEnd);
            certChainInfo.put("data", certChain);
        } else {
            certChainInfo.put("data", "无法提取证书链信息");
        }
        mainJson.put("证书链信息", certChainInfo);

        // 创建KeyDescription信息对象
        JSONObject keyDescInfo = new JSONObject();
        keyDescInfo.put("purpose", "获取密钥基本描述信息");
        keyDescInfo.put("method", "解析证书扩展字段中的密钥描述信息");

        // 提取KeyDescription部分
        int keyDescStart = certChainResult.indexOf("KeyDescription");
        int keyDescEnd = certChainResult.indexOf("\n\n", keyDescStart);
        if (keyDescStart >= 0 && keyDescEnd >= 0) {
            String keyDesc = certChainResult.substring(keyDescStart, keyDescEnd);
            keyDescInfo.put("data", keyDesc);
        } else {
            keyDescInfo.put("data", "无法提取密钥描述信息");
        }
        mainJson.put("KeyDescription", keyDescInfo);

        // 创建AuthorizationList信息对象
        JSONObject authListInfo = new JSONObject();
        authListInfo.put("purpose", "获取密钥授权和安全性信息");
        authListInfo.put("method", "解析证书扩展字段中的授权列表信息");

        // 提取AuthorizationList部分
        int authListStart = certChainResult.indexOf("AuthorizationList");
        if (authListStart >= 0) {
            String authList = certChainResult.substring(authListStart);
            authListInfo.put("data", authList);
        } else {
            authListInfo.put("data", "无法提取授权列表信息");
        }
        mainJson.put("AuthorizationList", authListInfo);

        // 创建设备锁定状态对象
        JSONObject deviceLockInfo = new JSONObject();
        deviceLockInfo.put("purpose", "检查设备引导锁定状态");
        deviceLockInfo.put("method", "从KeyAttestation Root of Trust中提取设备锁定信息");
        deviceLockInfo.put("data", ka.isDeviceLocked() ? "已锁定" : "未锁定");
        mainJson.put("设备锁定状态", deviceLockInfo);

        // 将整个JSON包装在一个对象中返回
        JSONObject resultJson = new JSONObject();
        resultJson.put("result", mainJson);

        return resultJson;
    }

    // 辅助方法：JSON字符串转义
    private String jsonEscape(String input) {
        if (input == null) return "\"\"";
        String escaped = input.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
        return "\"" + escaped + "\"";
    }

    //------------------------------------------汇总----------------------------------------------------------
    public JSONObject total(Context context) throws IOException, JSONException {
        JSONObject combinedResult = new JSONObject();

        // 解析各个方法返回的JSON字符串
        JSONObject rc = new JSONObject(rootCheck().toString());
        JSONObject ec = new JSONObject(emulatorCheck(context).toString());
        JSONObject hc = new JSONObject(checkhook().toString());
        JSONObject fc = new JSONObject(checkFingerPrint(context).toString());
        JSONObject tc = new JSONObject(test(context).toString());
        JSONObject an = new JSONObject(appname(context).toString());
        JSONObject ct = new JSONObject(certinfo().toString());
        JSONObject df = new JSONObject(devicefeatures(context).toString());
        JSONObject ka = new JSONObject(keyattestion().toString());

        // 合并所有JSONObject到主结果中
        mergeJSONObjects(combinedResult, rc);
        mergeJSONObjects(combinedResult, ec);
        mergeJSONObjects(combinedResult, hc);
        mergeJSONObjects(combinedResult, fc);
        mergeJSONObjects(combinedResult, tc);
        mergeJSONObjects(combinedResult, an);
        mergeJSONObjects(combinedResult, ct);
        mergeJSONObjects(combinedResult, df);
        mergeJSONObjects(combinedResult, ka);

        return combinedResult;
    }
    private void mergeJSONObjects(JSONObject target, JSONObject source) throws JSONException {
        Iterator<String> keys = source.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            target.put(key, source.get(key));
        }
    }




}
