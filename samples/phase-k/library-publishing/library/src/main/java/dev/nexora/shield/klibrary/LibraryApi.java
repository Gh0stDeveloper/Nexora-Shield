package dev.nexora.shield.klibrary;

import android.content.Context;

public final class LibraryApi {
    private LibraryApi() {}

    public static String message(Context context) {
        return context.getString(R.string.library_message);
    }
}
