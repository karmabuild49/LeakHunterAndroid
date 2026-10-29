package com.leakhunter.mobile;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    private WebView webView;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        webView = new WebView(this);
        webView.setBackgroundColor(0xFF020604);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.getSettings().setDomStorageEnabled(false);
        webView.setWebChromeClient(new WebChromeClient());
        webView.setWebViewClient(new WebViewClient());
        webView.addJavascriptInterface(new Bridge(), "LeakHunter");
        setContentView(webView);
        webView.loadUrl("file:///android_asset/index.html");
    }

    private void sendResult(String callback, JSONObject result) {
        final String safeCallback = callback.replaceAll("[^A-Za-z0-9_]", "");
        final String json = result.toString();
        mainHandler.post(() -> webView.evaluateJavascript(
            "window.onNativeScanResult && window.onNativeScanResult('" + safeCallback + "', " +
            JSONObject.quote(json) + ")", null));
    }

    public class Bridge {
        @JavascriptInterface public void shareReport(String reportJson) {
            mainHandler.post(() -> {
                Intent intent = new Intent(Intent.ACTION_SEND);
                intent.setType("application/json");
                intent.putExtra(Intent.EXTRA_SUBJECT, "LeakHunter security report");
                intent.putExtra(Intent.EXTRA_TEXT, reportJson);
                startActivity(Intent.createChooser(intent, "Export LeakHunter report"));
            });
        }

        @JavascriptInterface public void scanDomain(String domain, String callback) {
            executor.execute(() -> {
                JSONObject result = new JSONObject();
                try {
                    String d = domain == null ? "" : domain.trim().toLowerCase();
                    if (!d.matches("(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}")) {
                        throw new IllegalArgumentException("Enter a valid domain such as example.com.");
                    }
                    result.put("domain", d);
                    JSONArray hosts = new JSONArray();
                    Set<String> found = new HashSet<>();
                    found.add(d);
                    String encoded = URLEncoder.encode("%." + d, "UTF-8");
                    URL ct = new URL("https://crt.sh/?q=" + encoded + "&output=json");
                    HttpURLConnection c = (HttpURLConnection) ct.openConnection();
                    c.setConnectTimeout(12000); c.setReadTimeout(12000);
                    c.setRequestProperty("User-Agent", "LeakHunter-DefensiveAudit/2.0");
                    int status = c.getResponseCode();
                    if (status == 200) {
                        BufferedReader br = new BufferedReader(new InputStreamReader(c.getInputStream()));
                        StringBuilder body = new StringBuilder(); String line;
                        while ((line = br.readLine()) != null && body.length() < 2_000_000) body.append(line);
                        br.close();
                        JSONArray rows = new JSONArray(body.toString());
                        for (int i=0; i<rows.length() && found.size()<100; i++) {
                            String names = rows.optJSONObject(i).optString("name_value", "");
                            for (String raw : names.split("\\n")) {
                                String h = raw.trim().toLowerCase().replaceFirst("^\\\\*\\\\.", "");
                                if (h.equals(d) || h.endsWith("." + d)) found.add(h);
                            }
                        }
                    }
                    c.disconnect();
                    List<String> sorted = new ArrayList<>(found); Collections.sort(sorted);
                    JSONArray checks = new JSONArray();
                    int dnsOk = 0, httpsOk = 0;
                    for (String host : sorted) {
                        JSONObject item = new JSONObject(); item.put("host", host);
                        try {
                            InetAddress[] addresses = InetAddress.getAllByName(host);
                            JSONArray ips = new JSONArray();
                            for (InetAddress addr : addresses) ips.put(addr.getHostAddress());
                            item.put("dns", "resolved"); item.put("addresses", ips); dnsOk++;
                        } catch (Exception ex) { item.put("dns", "failed"); }
                        try {
                            URL u = new URL("https://" + host + "/");
                            HttpURLConnection hc = (HttpURLConnection) u.openConnection();
                            hc.setConnectTimeout(7000); hc.setReadTimeout(7000);
                            hc.setRequestMethod("HEAD");
                            hc.setInstanceFollowRedirects(true);
                            int hs = hc.getResponseCode();
                            item.put("httpsStatus", hs);
                            item.put("hsts", hc.getHeaderField("Strict-Transport-Security") != null);
                            item.put("csp", hc.getHeaderField("Content-Security-Policy") != null);
                            item.put("xContentTypeOptions", hc.getHeaderField("X-Content-Type-Options") != null);
                            if (hs > 0) httpsOk++;
                            hc.disconnect();
                        } catch (Exception ex) { item.put("https", "unavailable"); }
                        checks.put(item);
                    }
                    result.put("status", "ok");
                    result.put("hostCount", checks.length());
                    result.put("dnsResolved", dnsOk);
                    result.put("httpsResponded", httpsOk);
                    result.put("hosts", checks);
                    result.put("note", "Public certificate-transparency data and basic DNS/HTTPS checks only. Results are not a full security audit.");
                } catch (Exception ex) {
                    try { result.put("status", "error"); result.put("message", ex.getMessage() == null ? "Scan failed." : ex.getMessage()); }
                    catch (Exception ignored) {}
                }
                sendResult(callback, result);
            });
        }
    }

    @Override public void onDestroy() {
        executor.shutdownNow();
        if (webView != null) webView.destroy();
        super.onDestroy();
    }
}
