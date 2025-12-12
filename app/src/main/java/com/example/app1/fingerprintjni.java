package com.example.app1;

public class fingerprintjni {

    static {
        System.loadLibrary("app1");
    }

    public native String getandroidid();

    public native String fingerprint();

    public native String netfp();

    public native String qemubkpt();

    public native String executespeed();

    public native String check();

    public native String mapscheck();

    public native String coursecheck();

    public native String parentscheck();

    public native String getappnames();

    public native String getcertificate();

    public native String getdevicefeatures();

}
