package com.example.app1;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import java.util.List;

public class appname {
    public String getAllAppNames(Context context){
        PackageManager pm = context.getPackageManager();
        ////获取到所有安装了的应用程序的信息，包括那些卸载了的，但没有清除数据的应用程序
        @SuppressLint("QueryPermissionsNeeded") List<PackageInfo> list2 = pm.getInstalledPackages(PackageManager.GET_UNINSTALLED_PACKAGES);
        StringBuilder appname = new StringBuilder(getAppNumber(context));

        for (PackageInfo packageInfo : list2) {
            //得到手机上已经安装的应用的名字,即在AndriodMainfest.xml中的app_name。
            String appName = packageInfo.applicationInfo.loadLabel(context.getPackageManager()).toString();
            //得到手机上已经安装的应用的图标,即在AndriodMainfest.xml中的icon。
            //Drawable drawable = packageInfo.applicationInfo.loadIcon(context.getPackageManager());
            //得到应用所在包的名字,即在AndriodMainfest.xml中的package的值。
            String packageName = packageInfo.packageName;
            appname.append(appName).append(":").append(packageName).append("\n");
        }
        return appname.toString();
    }

    private String getAppNumber(Context context){
        PackageManager pm = context.getPackageManager();
        ////获取到所有安装了的应用程序的信息，包括那些卸载了的，但没有清除数据的应用程序
        @SuppressLint("QueryPermissionsNeeded") List<PackageInfo> list2 = pm.getInstalledPackages(PackageManager.GET_UNINSTALLED_PACKAGES);

        int j=0;
        for (PackageInfo ignored : list2) {
            j++;
        }
        return "应用的总个数:" + j + "\n";
    }
}
