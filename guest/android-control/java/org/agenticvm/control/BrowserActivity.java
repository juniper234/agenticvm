package org.agenticvm.control;

import android.app.Activity;
import android.net.Uri;
import android.os.Bundle;
import android.view.inputmethod.EditorInfo;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;

/** Small guest-local browser using the system WebView and normal TLS checks. */
public final class BrowserActivity extends Activity {
    private WebView web;
    private EditText address;

    private void navigate(String value) {
        if (value == null || value.length() > 4096) return;
        Uri uri = Uri.parse(value.trim());
        if (!"https".equals(uri.getScheme()) && !"http".equals(uri.getScheme())) return;
        address.setText(uri.toString());
        web.loadUrl(uri.toString());
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(8, 64, 8, 16);
        LinearLayout toolbar = new LinearLayout(this);
        address = new EditText(this);
        address.setSingleLine(true);
        address.setContentDescription("agenticvm-browser-address");
        address.setInputType(android.text.InputType.TYPE_CLASS_TEXT | android.text.InputType.TYPE_TEXT_VARIATION_URI);
        address.setImeOptions(EditorInfo.IME_ACTION_GO);
        toolbar.addView(address, new LinearLayout.LayoutParams(0, -2, 1));
        Button go = new Button(this);
        go.setText("Go");
        go.setOnClickListener(view -> navigate(address.getText().toString()));
        toolbar.addView(go);
        root.addView(toolbar);
        web = new WebView(this);
        web.setContentDescription("agenticvm-browser-page");
        web.getSettings().setJavaScriptEnabled(true);
        web.getSettings().setDomStorageEnabled(true);
        web.getSettings().setMixedContentMode(android.webkit.WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.setWebViewClient(new WebViewClient());
        root.addView(web, new LinearLayout.LayoutParams(-1, 0, 1));
        setContentView(root);
        address.setOnEditorActionListener((view, action, event) -> {
            if (action == EditorInfo.IME_ACTION_GO) { navigate(address.getText().toString()); return true; }
            return false;
        });
        navigate(getIntent().getDataString());
    }

    @Override public void onBackPressed() {
        if (web.canGoBack()) web.goBack(); else super.onBackPressed();
    }

    @Override public void onDestroy() {
        web.destroy();
        super.onDestroy();
    }
}
