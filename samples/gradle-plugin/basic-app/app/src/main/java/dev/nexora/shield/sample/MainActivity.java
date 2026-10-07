package dev.nexora.shield.sample;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView text = new TextView(this);
        text.setText("Nexora Shield Phase J");
        text.setTextSize(22.0f);
        text.setPadding(48, 48, 48, 48);
        setContentView(text);
    }
}
