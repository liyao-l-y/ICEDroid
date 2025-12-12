package com.example.app1;

import android.util.Log;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class PmuDetector {
    private static final String TAG = "PmuDetector";

    public static class PmuDevice {
        public String name;
        public String type; // contents of "type" file if available
        public HashMap<String, String> events = new HashMap<>(); // eventName -> contents

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Device: ").append(name).append("\n");
            sb.append("  type: ").append(type).append("\n");
            sb.append("  events:\n");
            for (String k : events.keySet()) {
                sb.append("    ").append(k).append(" -> ").append(events.get(k)).append("\n");
            }
            return sb.toString();
        }
    }

    public static List<PmuDevice> detectViaSysFs() {
        List<PmuDevice> results = new ArrayList<>();
        File base = new File("/sys/bus/event_source/devices");
        if (!base.exists() || !base.isDirectory()) {
            Log.w(TAG, "/sys/bus/event_source/devices not available on this device");
            return results;
        }

        File[] deviceDirs = base.listFiles();
        if (deviceDirs == null) return results;

        for (File devDir : deviceDirs) {
            if (!devDir.isDirectory()) continue;
            PmuDevice dev = new PmuDevice();
            dev.name = devDir.getName();

            File typeFile = new File(devDir, "type");
            dev.type = safeReadFile(typeFile);

            File eventsDir = new File(devDir, "events");
            if (eventsDir.exists() && eventsDir.isDirectory()) {
                File[] eventFiles = eventsDir.listFiles();
                if (eventFiles != null) {
                    for (File evFile : eventFiles) {
                        if (!evFile.isFile()) continue;
                        String key = evFile.getName();
                        String value = safeReadFile(evFile);
                        if (value != null) {
                            dev.events.put(key, value.trim());
                        }
                    }
                }
            } else {
                File[] files = devDir.listFiles();
                if (files != null) {
                    for (File f : files) {
                        if (!f.isFile()) continue;
                        String name = f.getName();
                        if (name.equals("type") || name.equals("format")) continue;
                        if (f.length() > 4096) continue;
                        String val = safeReadFile(f);
                        if (val != null && val.length() > 0) {
                            dev.events.put(name, val.trim());
                        }
                    }
                }
            }

            results.add(dev);
        }

        return results;
    }

    private static String safeReadFile(File f) {
        if (f == null || !f.exists() || !f.isFile()) return null;
        InputStream in = null;
        BufferedReader br = null;
        try {
            in = new FileInputStream(f);
            br = new BufferedReader(new InputStreamReader(in));
            StringBuilder sb = new StringBuilder();
            String line;
            boolean firstLine = true;
            while ((line = br.readLine()) != null) {
                if (!firstLine) sb.append("\n");
                sb.append(line);
                firstLine = false;
            }
            return sb.toString();
        } catch (IOException e) {
            Log.w(TAG, "read file failed: " + f.getAbsolutePath(), e);
            return null;
        } finally {
            try { if (br != null) br.close(); } catch (IOException ignored) {}
            try { if (in != null) in.close(); } catch (IOException ignored) {}
        }
    }

    public static String runSimpleperfList() {
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", "simpleperf list 2>&1");
        pb.redirectErrorStream(true);
        Process p = null;
        BufferedReader br = null;
        try {
            p = pb.start();
            br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder out = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                out.append(line).append('\n');
            }
            try { p.waitFor(); } catch (InterruptedException ignored) {}
            return out.toString();
        } catch (IOException e) {
            Log.w(TAG, "runSimpleperfList failed", e);
            return null;
        } finally {
            try { if (br != null) br.close(); } catch (IOException ignored) {}
            if (p != null) p.destroy();
        }
    }

    public static String runSimpleperfRecordTest(int seconds) {
        String cmd = String.format("simpleperf record -o /data/local/tmp/perf.data -e cpu-cycles --duration %d 2>&1", seconds);
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
        pb.redirectErrorStream(true);
        Process p = null;
        BufferedReader br = null;
        try {
            p = pb.start();
            br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            StringBuilder out = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                out.append(line).append('\n');
            }
            try { p.waitFor(); } catch (InterruptedException ignored) {}
            return out.toString();
        } catch (IOException e) {
            Log.w(TAG, "runSimpleperfRecordTest failed", e);
            return null;
        } finally {
            try { if (br != null) br.close(); } catch (IOException ignored) {}
            if (p != null) p.destroy();
        }
    }
}
