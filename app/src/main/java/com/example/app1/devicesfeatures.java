package com.example.app1;

import android.content.Context;
import android.content.pm.FeatureInfo;
import android.content.pm.PackageManager;

import java.util.ArrayList;
import java.util.List;

public class devicesfeatures {
    public String features(Context context){
        List<String> f = checkDeviceFeatures(context);
        StringBuilder fr = new StringBuilder("支持软硬件：\n");
        for (String feature : f){
            fr.append(feature).append("\n");
        }

        return fr.toString();
    }

    private List<String> checkDeviceFeatures(Context context) {
        List<String> f = new ArrayList<>();
        PackageManager pm = context.getPackageManager();
        FeatureInfo[] features = pm.getSystemAvailableFeatures();
        for (FeatureInfo feature : features) {
            // 检查特征名称是否不为null
            if (feature.name != null) {
                f.add(feature.name); // 特征名称
            }
        }
        return f;
    }

}
