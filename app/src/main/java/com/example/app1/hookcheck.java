package com.example.app1;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import android.os.Process;
import android.util.Log;


public class hookcheck {
    public String checkfrida(){
        StringBuilder s = new StringBuilder();

        if(hasReadProcMaps("frida") | mCheckFridaTcp()){
            s.append("检测到frida");
        }
        s.append("未检测到frida");
        return s.toString();
    }

    public String checkxposed(){
        StringBuilder s = new StringBuilder();
        if(hasReadProcMaps("xposed") | checkXposedModules()){
            s.append("检测到xposed");
        }
        s.append("未检测到xposed");
        return s.toString();
    }

    private boolean hasReadProcMaps(String paramString) {
        try {
            Object localObject = new HashSet<>();
            BufferedReader localBufferedReader = new BufferedReader(new FileReader("/proc/" + Process.myPid() + "/maps"));
            for (; ; ) {
                String str = localBufferedReader.readLine();
                if (str == null) {
                    break;
                }
                if ((str.endsWith(".so")) || (str.endsWith(".jar"))) {
                    ((Set) localObject).add(str.substring(str.lastIndexOf(" ") + 1));
                }
            }
            localBufferedReader.close();
            localObject = ((Set) localObject).iterator();
            while (((Iterator<?>) localObject).hasNext()) {
                boolean bool = ((String) ((Iterator<?>) localObject).next()).contains(paramString);
                if (bool) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    private static final String TAG = "FridaChecker";
    private boolean mCheckFridaTcp() {
        String[] stringArrayTcp6;
        String[] stringArrayTcp;
        String tcpStringTcp6 = mReadFile("/proc/net/tcp6");
        String tcpStringTcp = mReadFile("/proc/net/tcp");
        boolean isFridaExits = false;

        if (!tcpStringTcp6.isEmpty()) {
            stringArrayTcp6 = tcpStringTcp6.split("\n");
            for (String sa : stringArrayTcp6) {
                if (sa.toLowerCase().contains(":69a2")) {
                    Log.e(TAG, "tcp文件中发现Frida特征");
                    isFridaExits = true;
                }
            }
        }
        if (!tcpStringTcp.isEmpty()) {
            stringArrayTcp = tcpStringTcp.split("\n");
            for (String sa : stringArrayTcp) {
                if (sa.toLowerCase().contains(":69a2")) {
                    Log.e(TAG, "tcp文件中发现Frida特征");
                    isFridaExits = true;
                }
            }
        }
        return isFridaExits;
    }

    private String mReadFile(String filePath) {
        StringBuilder stringBuilder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line).append("\n");
            }
        } catch (IOException e) {
            Log.e(TAG, "读取文件失败: " + e.getMessage());
        }
        return stringBuilder.toString().trim(); // 去掉多余的换行符
    }

    public boolean checkXposedModules() {
        String xposedDir = "/data/data/de.robv.android.xposed.installer";
        File dir = new File(xposedDir);
        return dir.exists(); // 检查Xposed安装目录是否存在
    }
}


