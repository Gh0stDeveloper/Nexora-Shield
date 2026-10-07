package dev.nexora.shield.kconsumer;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import dev.nexora.shield.klibrary.LibraryApi;

public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TextView view = new TextView(this);
        view.setText(LibraryApi.message(this));
        setContentView(view);
    }
}
