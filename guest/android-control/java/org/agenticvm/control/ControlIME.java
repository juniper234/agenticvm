package org.agenticvm.control;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.inputmethodservice.InputMethodService;
import android.view.inputmethod.InputConnection;

/** Shell-authorized Unicode input, with no network calls or logging. */
public final class ControlIME extends InputMethodService {
    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override public void onReceive(Context context, Intent intent) {
            InputConnection connection = getCurrentInputConnection();
            String text = intent.getStringExtra("text");
            if (connection == null || text == null || text.length() > 16384) {
                setResultCode(2);
                setResultData("No focused input connection");
                return;
            }
            boolean ok = connection.commitText(text, 1);
            setResultCode(ok ? 0 : 3);
            setResultData(ok ? "committed" : "rejected");
        }
    };
    @Override public void onCreate() {
        super.onCreate();
        IntentFilter filter = new IntentFilter("org.agenticvm.control.INPUT");
        // DUMP is held by the ADB shell. Ordinary installed applications cannot
        // inject text through this receiver, even though the action is public.
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            registerReceiver(receiver, filter, "android.permission.DUMP", null, Context.RECEIVER_EXPORTED);
        } else {
            registerReceiver(receiver, filter, "android.permission.DUMP", null);
        }
    }
    @Override public void onDestroy() {
        unregisterReceiver(receiver);
        super.onDestroy();
    }
    @Override public boolean onEvaluateInputViewShown() { return false; }
}
