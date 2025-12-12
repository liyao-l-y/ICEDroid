package com.example.app1;

import android.annotation.SuppressLint;
import android.os.IBinder;
import android.util.Log;

import java.lang.reflect.Method;

public class service {
    public void getservice(){
        try {
            // 获取vivo_fingerprint_service
            @SuppressLint("PrivateApi") Class<?> serviceManagerClass = Class.forName("android.os.ServiceManager");
            @SuppressLint("DiscouragedPrivateApi") Method getServiceMethod = serviceManagerClass.getDeclaredMethod("getService", String.class);
            IBinder binder = (IBinder) getServiceMethod.invoke(null, "IVivoBinderService");
            if (binder == null) {
                Log.e("VivoService", "Service not found or not available");
                return;
            }

        } catch (Exception e) {
            Log.e("VivoService", "Error accessing vivo fingerprint service", e);
        }

    }




}
