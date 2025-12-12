package com.example.app1;

import android.annotation.SuppressLint;
import android.app.AlarmManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;

import org.json.JSONException;

import java.io.IOException;
import java.util.Calendar;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import com.darvin.security.detectfrida;

public class MainActivity extends AppCompatActivity {
    result rs = new result();

    String rootcheck;
    String emulatorcheck;
    String hookcheck;
    String fingerprintcheck;
    String testcheck;
    String keyattestion;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
//------------------------------------------Root检测---------------------------------------------------
        try {
            rootcheck = rs.rootCheck().toString();
        } catch (IOException | JSONException e) {
            throw new RuntimeException(e);
        }
//------------------------------------------模拟器检测---------------------------------------------------
        try {
            emulatorcheck = rs.emulatorCheck(this).toString();
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
//------------------------------------------hook检测---------------------------------------------------
        try {
            hookcheck = rs.checkhook().toString();
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
//------------------------------------------指纹检测---------------------------------------------------
        try {
            fingerprintcheck = rs.checkFingerPrint(this).toString();
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
//------------------------------------------测试---------------------------------------------------
        try {
            testcheck = rs.test(this).toString();
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }
//------------------------------------------密钥认证---------------------------------------------
        try {
            keyattestion = rs.keyattestion().toString();
        } catch (JSONException e) {
            throw new RuntimeException(e);
        }

        checkSign();
        startScheduledTask();
        setDailyAlarm();

        TextView rc = findViewById(R.id.root);
        rc.setText(rootcheck);
        System.out.println(rootcheck);
        TextView ec = findViewById(R.id.emulator);
        ec.setText(emulatorcheck);
        TextView hc = findViewById(R.id.hook);
        hc.setText(hookcheck);
        TextView fc = findViewById(R.id.fingerprint);
        fc.setText(fingerprintcheck);
        TextView tc = findViewById(R.id.test);
        tc.setText(testcheck);
        TextView kc = findViewById(R.id.key);
        kc.setText(keyattestion);

        setupMenuSpinner();

        /*
        TextView st = findViewById(R.id.statusTitle);
        ImageView resultimage = findViewById(R.id.resultImage);

        if (risklevel.equals("风险")){
            resultimage.setImageResource(R.drawable.result_risk);
            st.setText("设备存在风险");
        } else if (risklevel.equals("可疑")) {
            resultimage.setImageResource(R.drawable.result_suspicious);
            st.setText("设备存在可疑痕迹");
        } else if (risklevel.equals("安全")) {
            resultimage.setImageResource(R.drawable.result_safe);
            st.setText("设备安全");
        }
        */
    }

    private void setupMenuSpinner() {
        Spinner menu = findViewById(R.id.menu);
        // 为 Spinner 设置自定义适配器来使下拉选项的文本颜色与设计匹配
        ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(
                this, R.array.menu, R.layout.spinner_item);
        adapter.setDropDownViewResource(R.layout.spinner_dropdown);
        menu.setAdapter(adapter);
        menu.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> parent, View view, int position, long id) {
                // 根据选择的位置执行相应的操作
                if (position == 0) {
                    // "menu" 选项 - 不执行任何操作
                } else if (position == 1) {// "获取完整检测结果"
                    try {
                        gettotal();
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    } catch (JSONException e) {
                        throw new RuntimeException(e);
                    }
                } else if (position == 2) {// "查看记录"
                    getrecord();

                } else if (position == 3) {// "更新内部文件"
                    try {
                        updateInternalFiles();
                    } catch (IOException | JSONException e) {
                        throw new RuntimeException(e);
                    }
                } else if (position == 4) {// "更新外部存储"
                    try {
                        updateExternalStorage();
                    } catch (IOException | JSONException e) {
                        throw new RuntimeException(e);
                    }
                } else if (position == 5) {// "传输数据"
                    senddata();
                }
                else if (position == 6) {// "传输数据"
                    detectfrida df = new detectfrida();
                    df.detectf();
                }
                // 选择操作后将 Spinner 重置回第一个选项
                menu.setSelection(0);
            }
            @Override
            public void onNothingSelected(AdapterView<?> parent) {
                // 不做任何事情
            }
        });
    }
    //菜单选项
    private void gettotal() throws IOException, JSONException {
        result rs = new result();
        Intent intent = new Intent(MainActivity.this, MainActivity2.class);
        intent.putExtra("s", rs.total(this).toString());
        startActivity(intent);
    }
    private void getrecord() {
        filewr fl = new filewr();
        //String fr = fl.bufferRead("a.txt");
        String fr = fl.readFromAppSpecificFile(this, "check.txt");

        Intent intent = new Intent(MainActivity.this, MainActivity2.class);
        intent.putExtra("s", fr);
        startActivity(intent);
    }
    private void updateInternalFiles() throws IOException, JSONException {
        result rs = new result();
        filewr fl = new filewr();
        fl.writeToAppSpecificFile(this, "check.txt",rs.total(this).toString());
        Toast.makeText(this,"保存成功",Toast.LENGTH_LONG).show();
    }
    private void updateExternalStorage() throws IOException, JSONException {
        result rs = new result();
        filewr fl = new filewr();
        // 使用新的兼容性更好的方法，传入Context参数
        fl.saveJsonToExternalStorage(this, rs.total(this), "ICEDroid.json");
    }
    private void senddata() {
        result rs = new result();
        senddata sd = new senddata();
        try {
            sd.sendDataToServer(this,rs.total(this).toString());
            Toast.makeText(this,"上传成功",Toast.LENGTH_LONG).show();
        } catch (JSONException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    //-----------------------------------------------签名校验------------------------------------------------------
    private void checkSign(){
        if(signCheck()) {
            Toast.makeText(this,"签名校验成功",Toast.LENGTH_LONG).show();
        }else{
            Toast.makeText(this,"签名校验失败",Toast.LENGTH_LONG).show();
        }
    }
    private boolean signCheck(){
        //默认密钥库签名
        String sc_default = "5F:49:E9:F6:AC:16:31:F7:9A:77:7F:1A:15:06:EE:84:48:1D:4D:DF";
        //自建密钥库签名
        String sc_myappkey = "4D:DD:19:7F:A2:A2:59:77:0F:F1:3A:EB:FE:DD:26:A4:C1:8A:80:AA";

        signcheck signCheck = new signcheck(this, sc_default);
        return signCheck.check();
    }
    //定时校验
    private void startScheduledTask() {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        scheduler.scheduleWithFixedDelay(this::signCheck, 0, 15, TimeUnit.SECONDS);
        Log.d("ScheduledTask", "signcheck executed");
    }
    private void setDailyAlarm() {
        AlarmManager aManager = (AlarmManager)this.getSystemService(Context.ALARM_SERVICE);
        Intent intent = new Intent(this, MyReceiver.class);
        PendingIntent pendingIntent = PendingIntent.getBroadcast(this, 0, intent, PendingIntent.FLAG_IMMUTABLE);
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.HOUR_OF_DAY, 24);
        calendar.set(Calendar.MINUTE, 0);
        calendar.set(Calendar.SECOND, 0);
        calendar.set(Calendar.MILLISECOND, 0);
        long triggerTime = calendar.getTimeInMillis();
        if (System.currentTimeMillis() > triggerTime) {
            calendar.add(Calendar.DAY_OF_YEAR, 1);
            triggerTime = calendar.getTimeInMillis();
        }
        long intervalMillis = AlarmManager.INTERVAL_DAY; // 每天
        aManager.setRepeating(AlarmManager.RTC_WAKEUP, triggerTime, intervalMillis, pendingIntent);
    }
    private static class MyReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            // 通过上下文调用 signCheck 方法
            if (context instanceof MainActivity) {
                ((MainActivity) context).signCheck();
                System.out.println("setDailyAlarm");
            }
        }
    }


}

