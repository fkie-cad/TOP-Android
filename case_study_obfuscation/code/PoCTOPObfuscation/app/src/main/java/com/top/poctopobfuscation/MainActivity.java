package com.top.poctopobfuscation;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

import com.top.poctopobfuscation.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'poctopobfuscation' library on application startup.
    static {
        System.loadLibrary("poctopobfuscation");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ActivityMainBinding binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        TextView tv = new TextView(this);
        setup();
        tv.setText(new String(Test.getText()));
        setContentView(tv);
    }

    public native void setup();
}