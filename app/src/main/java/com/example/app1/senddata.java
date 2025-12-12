package com.example.app1;

import android.content.Context;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class senddata {
    String mip = "192.168.31.206";
    String txyip = "101.33.208.98";
    String murl = "http://" + txyip + ":8000/learn/receive_file_content/";
    public void sendDataToServer(Context context , String data) throws JSONException {
        OkHttpClient client = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .build();

        JSONObject jsonObject = new JSONObject();
        jsonObject.put("content", data);

        RequestBody body = RequestBody.create(MediaType.get("application/json"), String.valueOf(jsonObject));

        Request request = new Request.Builder()
                .url(murl)
                .post(body)
                .build();

        client.newCall(request).enqueue(new Callback() {
            @Override
            public void onFailure(@NonNull Call call, @NonNull IOException e) {
                Log.e("Network", "Send failed: " + e.getMessage());
                e.printStackTrace(); // 添加完整堆栈跟踪
            }
            @Override
            public void onResponse(@NonNull Call call, @NonNull Response response) {
                try {
                    String body = response.body().string();
                    if (response.isSuccessful()) {
                        Log.d("Network", "Send success. Response: " + body);
                        Looper.prepare();
                        Toast.makeText(context ,"Send success.",Toast.LENGTH_LONG).show();
                        Looper.loop();
                    } else {
                        Log.e("Network", "Server error: " + response.code() + "\n" + body);
                        Looper.prepare();
                        Toast.makeText(context ,"Server error: " + response.code(),Toast.LENGTH_LONG).show();
                        Looper.loop();
                    }
                } catch (IOException e) {
                    Log.e("Network", "Response parsing error", e);
                }
            }
        });
    }
}
