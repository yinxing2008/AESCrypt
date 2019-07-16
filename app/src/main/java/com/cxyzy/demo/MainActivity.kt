package com.cxyzy.demo

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        encryptBtn.setOnClickListener {
            val encryptedStr = AesCryptUtil.encrypt("123456",clearTextET.text.toString())
            encryptedET.setText(encryptedStr)
        }

        decryptBtn.setOnClickListener {
            val encryptedStr = AesCryptUtil.decrypt("123456",encryptedET.text.toString())
            clearTextET.setText(encryptedStr)
        }
    }
}
