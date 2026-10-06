package com.recovery.app

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.recovery.app.model.RecoverableFile
import com.recovery.app.model.RecoverableRecord
import com.recovery.app.model.RecoveryResult
import com.recovery.app.model.RecoveryType
import com.recovery.app.preview.PreviewManager
import com.recovery.app.recovery.RecoveryEngine
import com.recovery.app.secure.SecureDelete
import com.recovery.app.util.RootShell
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * 主 ViewModel
 * 管理恢复和安全删除的状态与操作
 */
class MainViewModel : ViewModel() {

    private val recoveryEngine = RecoveryEngine()
    private val previewManager = PreviewManager()

    // ===== 恢复状态 =====
    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()

    private val _scanProgress = MutableStateFlow("")
    val scanProgress: StateFlow<String> = _scanProgress.asStateFlow()

    private val _recoveryResult = MutableStateFlow<RecoveryResult?>(null)
    val recoveryResult: StateFlow<RecoveryResult?> = _recoveryResult.asStateFlow()

    private val _rootAvailable = MutableStateFlow<Boolean?>(null)
    val rootAvailable: StateFlow<Boolean?> = _rootAvailable.asStateFlow()

    // ===== 安全删除状态 =====
    private val _isDeleting = MutableStateFlow(false)
    val isDeleting: StateFlow<Boolean> = _isDeleting.asStateFlow()

    private val _deleteProgress = MutableStateFlow("")
    val deleteProgress: StateFlow<String> = _deleteProgress.asStateFlow()

    private val _selectedFile = MutableStateFlow<String?>(null)
    val selectedFile: StateFlow<String?> = _selectedFile.asStateFlow()

    /**
     * 检查 Root 权限
     */
    fun checkRoot() {
        viewModelScope.launch {
            _rootAvailable.value = RootShell.isRootAvailable()
        }
    }

    /**
     * 启动恢复扫描
     */
    fun startRecovery(types: Set<RecoveryType>) {
        viewModelScope.launch {
            _isScanning.value = true
            _scanProgress.value = "准备中..."
            try {
                val result = recoveryEngine.recover(types) { progress ->
                    _scanProgress.value = progress
                }
                _recoveryResult.value = result
            } catch (e: Exception) {
                _scanProgress.value = "扫描失败: ${e.message}"
            } finally {
                _isScanning.value = false
            }
        }
    }

    /**
     * 恢复选中的文件
     */
    fun recoverFile(item: RecoverableFile, outputDir: String, onDone: (String?) -> Unit) {
        viewModelScope.launch {
            val path = recoveryEngine.recoverFile(item, outputDir)
            onDone(path)
        }
    }

    /**
     * 安全删除文件
     */
    fun secureDelete(path: String, passes: Int = 3, onDone: (Boolean) -> Unit) {
        viewModelScope.launch {
            _isDeleting.value = true
            _deleteProgress.value = "正在安全删除..."
            val success = SecureDelete.deleteFile(path, passes)
            _isDeleting.value = false
            _deleteProgress.value = if (success) "删除成功" else "删除失败"
            onDone(success)
        }
    }

    /**
     * 获取文件预览信息
     */
    suspend fun getFilePreview(item: RecoverableFile) = previewManager.previewFile(item)

    /**
     * 获取记录预览信息
     */
    fun getRecordPreview(record: RecoverableRecord) = previewManager.previewRecord(record)

    /**
     * 获取待删除文件预览
     */
    fun getDeletePreview(path: String) = previewManager.previewFileForDelete(path)

    fun setSelectedFile(path: String?) {
        _selectedFile.value = path
    }
}
