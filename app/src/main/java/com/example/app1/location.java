package com.example.app1;

import android.content.Context;
import android.location.Address;
import android.location.Geocoder;
import android.location.Location;
import android.location.LocationManager;
import android.util.Log;

import java.io.IOException;
import java.util.List;

import android.Manifest;
import android.content.pm.PackageManager;
import android.widget.Toast;

public class location {
    public String getProvince(Context context) {
        Log.i("GPS: ", "getProvince");
        LocationManager locationManager = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);        // 默认Android GPS定位实例

        Location location = null;
        // 是否已经授权
        if (context.checkSelfPermission(Manifest.permission.ACCESS_COARSE_LOCATION) == PackageManager.PERMISSION_GRANTED){
            location = locationManager.getLastKnownLocation(LocationManager.PASSIVE_PROVIDER);      // 其他应用使用定位更新了定位信息 需要开启GPS
        }

        StringBuilder l = new StringBuilder();
        if(location != null) {
            Log.i("GPS: ", "获取位置信息成功");
            Log.i("GPS: ","经度：" + location.getLatitude());
            Log.i("GPS: ","纬度：" + location.getLongitude());
            // 获取地址信息
            l.append("经度：").append(location.getLatitude()).append("\n");
            l.append("纬度：").append(location.getLongitude()).append("\n");
            l.append("地址：").append(getAddress(location.getLatitude(),location.getLongitude(),context)).append("\n");
            Log.i("GPS: ",l.toString());
        } else {
            Log.i("GPS: ", "获取位置信息失败，请检查是否开启GPS,是否授权");
            Toast.makeText(context,"获取位置信息失败，请检查是否开启GPS,是否授权",Toast.LENGTH_LONG).show();
        }
        return l.toString();
    }

    //根据经度纬度 获取国家，省份
    public String getAddress(double latitude, double longitude, Context context) {
        String cityName = "";
        List<Address> addList = null;
        Geocoder ge = new Geocoder(context);
        try {
            addList = ge.getFromLocation(latitude, longitude, 1);
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (addList != null && !addList.isEmpty()) {
            for (int i = 0; i < addList.size(); i++) {
                Address ad = addList.get(i);
                cityName += ad.getCountryName() + " " + ad.getLocality();
            }
        }
        return cityName;
    }
}
