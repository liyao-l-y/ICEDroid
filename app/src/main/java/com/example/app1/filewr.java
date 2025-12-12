package com.example.app1;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Environment;
import android.util.Log;

import androidx.core.content.ContextCompat;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class filewr {
    //---------------------------------------------------------外部存储-----------------------------------------------------
    public void bufferSave(String msg, String filename) {
        // 修改为使用上下文获取应用专属的外部存储目录
        File externalDir = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS), "app1");
        if (!externalDir.exists()) {
            externalDir.mkdirs();
        }
        File file = new File(externalDir, filename);
        
        // 先读取原有内容
        StringBuilder originalContent = new StringBuilder();
        try {
            if (file.exists()) {
                BufferedReader bfr = new BufferedReader(new FileReader(file));
                String line;
                while ((line = bfr.readLine()) != null) {
                    originalContent.append(line).append("\n");
                }
                bfr.close();
            }
        } catch (IOException e) {
            Log.w("bufferSaveException", e.getMessage(), e);
        }
        
        // 将要写入的内容以换行符分割
        String[] newContentLines = msg.split("\n");
        String[] originalLines = originalContent.toString().split("\n");
        
        // 对比并打印变化的部分
        for (int i = 0; i < Math.max(newContentLines.length, originalLines.length); i++) {
            String newLine = i < newContentLines.length ? newContentLines[i] : "";
            String originalLine = i < originalLines.length ? originalLines[i] : "";
            if (!newLine.equals(originalLine)) {
                System.out.println("变化的部分 (行 " + (i + 1) + "):");
                System.out.println("原内容: " + originalLine);
                System.out.println("新内容: " + newLine);
            }
        }
        
        // 覆盖写入新内容
        try {
            BufferedWriter bfw = new BufferedWriter(new FileWriter(file, false));//追加写入或覆盖写入
            bfw.write(msg);
            bfw.newLine();
            bfw.flush();
            bfw.close();
            Log.d("bufferSave", "保存成功到: " + file.getAbsolutePath());
        } catch (IOException e1) {
            Log.w("bufferSaveException", e1.getMessage(), e1);
        }
    }

    public String bufferRead(String filename) {
        // 修改为使用上下文获取应用专属的外部存储目录
        File externalDir = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS), "app1");
        File file = new File(externalDir, filename);
        
        if (!file.exists()) {
            return "文件不存在";
        }
        
        try {
            BufferedReader bfr = new BufferedReader(new FileReader(file));
            String line = bfr.readLine();
            StringBuilder sb = new StringBuilder("读取历史记录：\n");
            while (line != null) {
                sb.append(line);
                sb.append("\n");
                line = bfr.readLine();
            }
            bfr.close();

            Log.d("buffer", "bufferRead: " + sb);
            return sb.toString();
        } catch (IOException e) {
            Log.w("bufferReadException", e.getMessage(), e);
        }
        return "读取失败";
    }
    
    // 兼容性更好的外部存储方法，需要Context
    public void saveToExternalStorage(Context context, String msg, String filename) {

        // 获取应用专属的外部存储目录
        File externalDir = context.getExternalFilesDir(null);
        if (externalDir == null) {
            Log.e("FileStorage", "外部存储不可用");
            return;
        }

        // 确保目录存在
        if (!externalDir.exists()) {
            boolean created = externalDir.mkdirs();
            if (!created) {
                Log.e("FileStorage", "无法创建目录: " + externalDir.getAbsolutePath());
                return;
            }
        }

        File file = new File(externalDir, filename);

        try {
            FileOutputStream fos = new FileOutputStream(file);
            OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
            BufferedWriter bfw = new BufferedWriter(osw);

            bfw.write(msg);
            bfw.flush();
            bfw.close();
            osw.close();
            fos.close();

            Log.d("FileStorage", "保存成功到: " + file.getAbsolutePath());
        } catch (IOException e) {
            Log.e("FileStorage", "写入文件失败: " + e.getMessage(), e);
        }
    }

    public void saveJsonToExternalStorage(Context context, JSONObject jsonObject, String filename) {
        // 确保文件名以.json结尾
        if (!filename.endsWith(".json")) {
            filename = filename + ".json";
        }

        // 获取应用专属的外部存储目录
        File externalDir = context.getExternalFilesDir(null);
        if (externalDir == null) {
            Log.e("FileStorage", "外部存储不可用");
            return;
        }

        // 确保目录存在
        if (!externalDir.exists()) {
            boolean created = externalDir.mkdirs();
            if (!created) {
                Log.e("FileStorage", "无法创建目录: " + externalDir.getAbsolutePath());
                return;
            }
        }

        File file = new File(externalDir, filename);

        try {
            // 将JSONObject转换为格式化的JSON字符串
            String jsonString = jsonObject.toString(4); // 使用4个空格缩进格式化JSON

            FileOutputStream fos = new FileOutputStream(file);
            OutputStreamWriter osw = new OutputStreamWriter(fos, StandardCharsets.UTF_8);
            BufferedWriter bfw = new BufferedWriter(osw);

            bfw.write(jsonString);
            bfw.flush();
            bfw.close();
            osw.close();
            fos.close();

            Log.d("FileStorage", "JSON保存成功到: " + file.getAbsolutePath());
        } catch (IOException | JSONException e) {
            Log.e("FileStorage", "写入JSON文件失败: " + e.getMessage(), e);
        }
    }



    public String readFromExternalStorage(Context context, String filename) {
        // 获取应用专属的外部存储目录
        File externalDir = context.getExternalFilesDir(null);
        if (externalDir == null) {
            Log.e("FileStorage", "外部存储不可用");
            return "外部存储不可用";
        }
        
        File file = new File(externalDir, filename);
        if (!file.exists()) {
            return "文件不存在";
        }
        
        try {
            BufferedReader bfr = new BufferedReader(new FileReader(file));
            String line = bfr.readLine();
            StringBuilder sb = new StringBuilder("读取历史记录：\n");
            while (line != null) {
                sb.append(line);
                sb.append("\n");
                line = bfr.readLine();
            }
            bfr.close();
            Log.d("readFromExternalStorage", "读取成功");
            return sb.toString();
        } catch (IOException e) {
            Log.w("readFromExternalStorage", e.getMessage(), e);
        }
        return "读取失败";
    }
//---------------------------------------------------------专属文件-----------------------------------------------------
    // 写入文件方法
    public void writeToAppSpecificFile(Context context, String filename, String data) {
        try (FileOutputStream fos = context.openFileOutput(filename, Context.MODE_PRIVATE)) {
            fos.write(data.getBytes(StandardCharsets.UTF_8));
            Log.d("writeToAppSpecificFile", "写入成功");
        } catch (IOException e) {
            Log.e("FileStorage", "Write error: " + e.getMessage());
        }
    }

    // 读取文件方法
    public String readFromAppSpecificFile(Context context, String filename) {
        try (FileInputStream fis = context.openFileInput(filename)) {
            ByteArrayOutputStream result = new ByteArrayOutputStream();
            byte[] buffer = new byte[50000];
            int length;
            while ((length = fis.read(buffer)) != -1) {
                result.write(buffer, 0, length);
            }
            Log.d("readFromAppSpecificFile", "读取成功");
            return result.toString(StandardCharsets.UTF_8.name());
        } catch (IOException e) {
            Log.e("FileStorage", "Read error: " + e.getMessage());
            return null;
        }
    }


}
