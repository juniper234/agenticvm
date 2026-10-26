package org.agenticvm.control;

import android.app.Activity;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Visible acceptance fixture for taps, input and cold-boot persistence. */
public final class MainActivity extends Activity {
    private static String checksum(String value) {
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder text = new StringBuilder("SHA256 ");
            for (byte b : digest) text.append(String.format(java.util.Locale.ROOT, "%02x", b & 255));
            return text.toString();
        } catch (java.security.NoSuchAlgorithmException error) { throw new IllegalStateException(error); }
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(32, 72, 32, 32);
        TextView title = new TextView(this);
        title.setText("AgenticVM Android");
        title.setTextSize(28);
        layout.addView(title);
        EditText editor = new EditText(this);
        editor.setContentDescription("agenticvm-editor");
        editor.setText(getPreferences(MODE_PRIVATE).getString("value", ""));
        editor.setSingleLine(false);
        editor.setMinLines(3);
        layout.addView(editor, new LinearLayout.LayoutParams(-1, -2));
        TextView status = new TextView(this);
        status.setContentDescription("agenticvm-status");
        status.setText(checksum(editor.getText().toString()));
        Button save = new Button(this);
        save.setText("Save across restart");
        save.setContentDescription("agenticvm-save");
        save.setOnClickListener(view -> {
            boolean ok = getPreferences(MODE_PRIVATE).edit().putString("value", editor.getText().toString()).commit();
            status.setText(ok ? checksum(editor.getText().toString()) : "Save failed");
        });
        layout.addView(save);
        layout.addView(status);
        setContentView(layout);
    }
}
