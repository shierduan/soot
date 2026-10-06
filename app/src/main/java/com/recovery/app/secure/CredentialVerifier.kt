package com.recovery.app.secure

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts

/**
 * 锁屏凭证验证器
 *
 * 使用 Android 系统的 KeyguardManager 启动系统级锁屏验证界面，
 * 要求用户输入 PIN / 图案 / 密码 / 生物识别。
 *
 * 验证通过后才能执行安全删除操作，防止他人恶意擦除数据。
 *
 * API: KeyguardManager.createConfirmDeviceCredentialIntent(title, description)
 */
class CredentialVerifier(private val context: Context) {

    /**
     * 检查设备是否已设置锁屏密码
     */
    fun isDeviceSecure(): Boolean {
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            keyguard.isDeviceSecure
        } else {
            @Suppress("DEPRECATION")
            keyguard.isKeyguardSecure
        }
    }

    /**
     * 启动锁屏验证
     *
     * @param launcher ActivityResultLauncher 用于接收验证结果
     * @return true 表示成功启动验证界面
     */
    fun verify(
        launcher: ActivityResultLauncher<Intent>,
        title: String = "验证锁屏密码",
        description: String = "请输入锁屏密码以执行安全删除"
    ): Boolean {
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        val intent = keyguard.createConfirmDeviceCredentialIntent(title, description)
        return if (intent != null) {
            launcher.launch(intent)
            true
        } else {
            // 设备未设置锁屏，直接允许
            true
        }
    }

    companion object {
        /**
         * 创建用于接收验证结果的 ActivityResultLauncher
         */
        fun createLauncher(
            registry: androidx.activity.result.ActivityResultRegistry,
            onResult: (Boolean) -> Unit
        ): ActivityResultLauncher<Intent> {
            return registry.register(
                "credential_verify",
                ActivityResultContracts.StartActivityForResult()
            ) { result ->
                onResult(result.resultCode == android.app.Activity.RESULT_OK)
            }
        }
    }
}
