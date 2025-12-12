package com.example.app1;

import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.TextView;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.darvin.security.detectfrida;
import top.canyie.magiskkiller.killmagisk;
import io.github.vvb2060.xposeddetector.xposeddetector;


public class MainActivity2 extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main2);

        Intent intent = getIntent();

//------------------------------------------aar---------------------------------------------------
        if (intent.getBooleanExtra("detectfrida",false)){
            detectfrida df = new detectfrida();
            df.detectf();
        } else if (intent.getBooleanExtra("magiskkiller",false)) {
            killmagisk km = new killmagisk(this);

            km.setViews(findViewById(R.id.text));
            km.startDetection();
        } else if (intent.getBooleanExtra("xposeddetector",false)) {
            xposeddetector xd = new xposeddetector(this);

            xd.setViews(findViewById(R.id.text));
            xd.detectxposed();
        }


//------------------------------------------文本---------------------------------------------------

        String btn = intent.getStringExtra("btn");
        String s = intent.getStringExtra("s");
        TextView title = findViewById(R.id.title);
        TextView textView = findViewById(R.id.text);
        title.setText(btn);
        textView.setText(s);
//------------------------------------------返回---------------------------------------------------
        Button button = findViewById(R.id.button);
        button.setOnClickListener(view -> finish());

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });
    }
}