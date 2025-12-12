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
        s.append("CheckFridainProcMaps:").append(hasReadProcMaps("frida"))
         .append("CheckFridainTcp:").append(mCheckFridaTcp());
        return s.toString();
    }

    public String checkxposed(){
        StringBuilder s = new StringBuilder();
        s.append("CheckFridainProcMaps:").append(hasReadProcMaps("xposed"))
         .append("CheckFridainTcp:").append(mCheckFridaTcp());
        return s.toString();
    }

    private String hasReadProcMaps(String paramString) {
        try {
            StringBuilder result = new StringBuilder();
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
                    result.append(((String) ((Iterator<?>) localObject).next()));

                }
            }
            return result.toString();
        } catch (Exception e) {
            return e.toString();
        }
    }

    private String mCheckFridaTcp() {
        StringBuilder result = new StringBuilder();
        String[] stringArrayTcp6;
        String[] stringArrayTcp;
        String tcpStringTcp6 = mReadFile("/proc/net/tcp6");
        String tcpStringTcp = mReadFile("/proc/net/tcp");
        if (!tcpStringTcp6.isEmpty()) {
            stringArrayTcp6 = tcpStringTcp6.split("\n");
            for (String sa : stringArrayTcp6) {
                if (sa.toLowerCase().contains(":69a2")) {
                    result.append(sa.toLowerCase());
                }
            }
        }
        if (!tcpStringTcp.isEmpty()) {
            stringArrayTcp = tcpStringTcp.split("\n");
            for (String sa : stringArrayTcp) {
                if (sa.toLowerCase().contains(":69a2")) {
                    result.append(sa.toLowerCase());
                }
            }
        }
        return result.toString();
    }

    private String mReadFile(String filePath) {
        StringBuilder stringBuilder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                stringBuilder.append(line).append("\n");
            }
        } catch (IOException e) {
            return e.toString();
        }
        return stringBuilder.toString().trim(); // 去掉多余的换行符
    }

}


