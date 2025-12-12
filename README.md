# ICEDroid：Intrusion Countermeasure Electronics Droid
ICE（Intrusion Countermeasure Electronics：侵入対抗電子機器）： An Android app environment detection SDK, responsible for countering hooks and collecting risk control environment data.


> ACKNOWLEDGMENTS : This work was partially supported by the Zhongguancun Academy.  


项目流程图：

![image](https://github.com/user-attachments/assets/6dbdb934-9e5f-499b-a267-717da521ae56)


demo：


https://github.com/user-attachments/assets/0254b9b5-4ba7-44f6-b22b-ef183d9ca21d


https://github.com/user-attachments/assets/3ff04726-1217-4790-99f9-499d1650964a



**使用AAR**

**项目语言：Java，kotlin**

### **step1：导入aar项目**

将aar文件放置在project目录格式中app文件夹下（与src同级）的libs文件夹（没有可新建）内。

### **step2：修改配置文件**

在settings.gradle.kst文件（与app文件夹同级）的`repositories`部分中添加代码：

```kotlin
flatDir {
            dirs("libs")
        }
```

完整代码：

```kotlin
pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()

        flatDir {
            dirs("libs")
        }

    }
}
```

在app文件夹下的build.gradle.kts文件中的`dependencies`部分添加依赖：

```kotlin
implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))
```

完整代码：

```kotlin
dependencies {

    implementation(libs.appcompat)
    implementation(libs.material)
    implementation(libs.activity)
    implementation(libs.constraintlayout)

    implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar"))))

    testImplementation(libs.junit)
    androidTestImplementation(libs.ext.junit)
    androidTestImplementation(libs.espresso.core)


}
```

添加完成后点击上方`sync now`进行同步。

### **step3：引用aar内的类**

使用impor导入需要引用的类：

```java
import com.example.app1.result;
```

在程序中使用：

```java
result r = new result();
String s;
try {
    s = r.rootCheck();
} catch (IOException e) {
    throw new RuntimeException(e);
}
ystem.out.println(s);
```

## 可供使用的类及方法

### result类：

rootCheck()：检测设备是否root

emulatorCheck(Context context)：检测设备是否是模拟器

checkFingerPrint(Context context)：检测设备指纹

checkhook()：检测设备是否安装hook相关工具

fingerprintjni()：全部的jni属性检测方法

test(Context context)：部分设备属性

appname(Context context)：设备已安装app

certinfo()：设备已安装证书

devicefeatures(Context context)：设备支持的软硬件

total(Context context)：检测项汇总

### rootcheck类：

checkSuCommand()：检查SU命令

checkRootFiles()：检查root特征文件

checkSystemTags()：检查系统tag

checkMountInfo()：检查分区读写模式

checkSystemProperty()：检查系统属性:异常

checkSELinuxStatus()：检查SELinux状态

isBootloaderUnlocked()：检查Bootloader状态

checkTEE()：检查TEE状态

checkFP()：检查系统指纹属性是否一致

### emulatorcheck类：

checkfingerprint()：检查设备指纹

checkBuild()：检查设备属性

checkHardwareFeatures(context)：检查硬件特征

checkFileSystem()：检查文件系统

checkRunningApps()：检查运行程序

checkBattery(context)：检查电池状态

### fingerprint类：

getDeviceID(ContentResolver contentResolver)：获取设备ID

getLocalMacAddress()：获取网络地址

getSystemProperties()：获取设备属性

### hookcheck类：

checkfrida()：检测是否有frida相关特征

### fingerprintjni类：

fingerprint()：系统指纹

netfp()：网络地址

check()、mapscheck()：hook检测

getappnames()：检测设备已安装应用

getcertificate()：检测系统已安装证书

getdevicefeatures()：检测支持软硬件

### fptest类：

getProperties(Context context)：获取部分设备属性

### appname类：

getAllAppNames(Context context)：获取已安装应用

### certificate类：

listInstalledCertificates()：获取系统证书

### devicesfeatures类：

features(Context context)：获取支持软硬件

### signcheck类：

check()：签名校验

### filewr类：

bufferSave(String msg,String filename)：写入文件并输出有改变的部分

bufferRead(String filename)：读取文件

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=liyao-l-y/ICEDroid&type=Date)](https://www.star-history.com/#liyao-l-y/ICEDroid&Date)
