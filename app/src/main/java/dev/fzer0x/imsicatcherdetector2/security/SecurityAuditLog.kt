package dev.fzer0x.imsicatcherdetector2.security

import android.content.Context
import android.util.Log
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Sicherheits-Audit-Log System
 * Protokolliert alle sicherheitsrelevanten Ereignisse für Forensik und Debugging
 */
object SecurityAuditLog {
    private val TAG = "SecurityAudit"
    private val auditQueue = ConcurrentLinkedQueue<AuditEntry>()
    private val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US)
    private val MAX_QUEUE_SIZE = 10000
    private val CLEANUP_THRESHOLD = 8000

    data class AuditEntry(
        val timestamp: Long = System.currentTimeMillis(),
        val severity: AuditSeverity,
        val category: AuditCategory,
        val message: String,
        val details: Map<String, Any> = emptyMap(),
        val stackTrace: String? = null,
        // Enhanced forensic fields
        val deviceId: String? = null,
        val userId: String? = null,
        val sessionId: String? = null,
        val packageName: String? = null,
        val threadName: String? = null,
        val processId: Int? = null
    )

    enum class AuditSeverity {
        INFO, WARNING, ERROR, CRITICAL
    }

    enum class AuditCategory {
        // Security Events
        INPUT_VALIDATION_FAILED,
        API_CALL_BLOCKED,
        CERTIFICATE_PIN_VERIFICATION_FAILED,
        UNAUTHORIZED_ACCESS_ATTEMPT,
        BROADCAST_SIGNATURE_VERIFICATION_FAILED,
        
        // Enhanced Security Events
        ROOT_ACCESS_DETECTED,
        ROOT_COMMAND_EXECUTED,
        MAGISK_MODULE_STATE_CHANGED,
        KERNELSU_MODULE_STATE_CHANGED,
        XPOSED_HOOK_STATUS_CHANGED,
        SYSTEM_PROPERTY_MODIFIED,
        BINARY_EXECUTION_ATTEMPT,
        SU_ACCESS_GRANTED,
        SU_ACCESS_DENIED,
        
        // Network & Radio Events
        IMSI_CATCHER_DETECTED,
        CIPHERING_OFF_DETECTED,
        SILENT_SMS_DETECTED,
        NETWORK_DOWNGRADE_DETECTED,
        BASEBAND_VULNERABILITY_FOUND,
        CELL_TOWER_ANOMALY_DETECTED,
        RRC_STATE_ANOMALY,
        TIMING_ADVANCE_ANOMALY,
        SIGNAL_STRENGTH_ANOMALY,
        NEIGHBOR_CELL_ANOMALY,
        HANDOVER_FAILURE,
        REGISTRATION_REJECTION,
        
        // 5G/SA Specific Events
        NR_STANDALONE_DETECTED,
        NR_NON_STANDALONE_DETECTED,
        MMWAVE_BAND_DETECTED,
        DUAL_CONNECTIVITY_ESTABLISHED,
        NR_SECURITY_CONTEXT_MODIFIED,
        
        // System Events
        SERVICE_STARTED,
        SERVICE_STOPPED,
        BOOT_COMPLETED,
        SHUTDOWN_INITIATED,
        XPOSED_HOOK_LOADED,
        XPOSED_HOOK_FAILED,
        MODULE_INSTALLATION_ATTEMPTED,
        MODULE_REMOVAL_ATTEMPTED,
        SYSTEM_REBOOT_REQUESTED,
        
        // Performance Events
        REGEX_TIMEOUT,
        PROCESS_TIMEOUT,
        API_TIMEOUT,
        MEMORY_THRESHOLD_EXCEEDED,
        CPU_THRESHOLD_EXCEEDED,
        DATABASE_OPERATION_FAILED,
        CACHE_OVERFLOW,
        
        // Configuration Events
        SECURITY_SETTING_CHANGED,
        KEY_ROTATION_PERFORMED,
        DATABASE_MIGRATION_STARTED,
        DATABASE_MIGRATION_COMPLETED,
        USER_PREFERENCE_MODIFIED,
        THRESHOLD_ADJUSTED,
        API_KEY_UPDATED,
        
        // Forensic Events
        PCAP_EXPORT_STARTED,
        PCAP_EXPORT_COMPLETED,
        LOCATION_DATA_ACCESSED,
        CELL_DATABASE_QUERIED,
        EXTERNAL_API_SYNC_STARTED,
        EXTERNAL_API_SYNC_COMPLETED,
        
        // Panic & Recovery Events
        PANIC_MODE_ACTIVATED,
        PANIC_MODE_DEACTIVATED,
        EXTENDED_PANIC_ACTIVATED,
        SYSTEM_RECOVERY_INITIATED,
        RADIO_HARDWARE_DISABLED,
        NETWORK_ISOLATION_ENABLED,
        
        // Blocking & Mitigation Events
        GSM_CONNECTION_BLOCKED,
        A5_CIPHER_REJECTED,
        SILENT_SMS_BLOCKED,
        CELL_TOWER_BLOCKED,
        IP_ADDRESS_BLOCKED,
        MAC_ADDRESS_BLOCKED,
        MITIGATION_TRIGGERED,
        AUTOMATED_RESPONSE_EXECUTED
    }

    fun log(
        severity: AuditSeverity,
        category: AuditCategory,
        message: String,
        details: Map<String, Any> = emptyMap(),
        throwable: Throwable? = null
    ) {
        try {
            val stackTrace = throwable?.let { formatStackTrace(it) }
            
            // Auto-populate enhanced forensic fields
            val enhancedDetails = details.toMutableMap().apply {
                put("threadName", Thread.currentThread().name)
                try {
                    put("processId", android.os.Process.myPid())
                } catch (e: Exception) {
                    // Fallback for contexts where Process API not available
                }
            }
            
            val entry = AuditEntry(
                severity = severity,
                category = category,
                message = message,
                details = enhancedDetails,
                stackTrace = stackTrace,
                threadName = Thread.currentThread().name,
                processId = try { android.os.Process.myPid() } catch (e: Exception) { null }
            )

            auditQueue.offer(entry)

            // Enhanced queue management with cleanup
            if (auditQueue.size > MAX_QUEUE_SIZE) {
                // Remove oldest entries to prevent memory issues
                val removeCount = auditQueue.size - CLEANUP_THRESHOLD
                repeat(removeCount) {
                    auditQueue.poll()
                }
                Log.w(TAG, "Audit queue cleanup: removed $removeCount old entries")
            }

            // Log to Android Log based on severity
            val logMessage = formatLogMessage(entry)
            when (severity) {
                AuditSeverity.INFO -> Log.i(TAG, logMessage)
                AuditSeverity.WARNING -> Log.w(TAG, logMessage)
                AuditSeverity.ERROR -> Log.e(TAG, logMessage, throwable)
                AuditSeverity.CRITICAL -> {
                    Log.e(TAG, "⚠️ CRITICAL SECURITY EVENT ⚠️")
                    Log.e(TAG, logMessage, throwable)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error logging audit entry: ${e.message}")
        }
    }

    // Enhanced Security Logging Methods
    
    fun logInputValidationFailed(field: String, value: Any, reason: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.INPUT_VALIDATION_FAILED,
            "Input validation failed for field: $field",
            mapOf(
                "field" to field,
                "reason" to reason,
                "valueLength" to value.toString().length
            )
        )
    }
    
    fun logRootAccessDetected(method: String, success: Boolean, details: String = "") {
        log(
            if (success) AuditSeverity.WARNING else AuditSeverity.INFO,
            AuditCategory.ROOT_ACCESS_DETECTED,
            "Root access detected via $method",
            mapOf(
                "method" to method,
                "success" to success,
                "details" to details,
                "timestamp" to System.currentTimeMillis()
            )
        )
    }
    
    fun logRootCommandExecuted(command: String, result: String, duration: Long) {
        log(
            AuditSeverity.INFO,
            AuditCategory.ROOT_COMMAND_EXECUTED,
            "Root command executed: ${command.take(50)}...",
            mapOf(
                "command" to command.take(100),
                "result" to result.take(100),
                "durationMs" to duration,
                "commandLength" to command.length
            )
        )
    }
    
    fun logModuleStateChanged(moduleType: String, oldState: String, newState: String, version: String = "") {
        log(
            AuditSeverity.INFO,
            when (moduleType.lowercase()) {
                "magisk" -> AuditCategory.MAGISK_MODULE_STATE_CHANGED
                "kernelsu" -> AuditCategory.KERNELSU_MODULE_STATE_CHANGED
                else -> AuditCategory.MODULE_INSTALLATION_ATTEMPTED
            },
            "$moduleType module state changed: $oldState -> $newState",
            mapOf(
                "moduleType" to moduleType,
                "oldState" to oldState,
                "newState" to newState,
                "version" to version
            )
        )
    }
    
    fun logSystemPropertyModified(property: String, oldValue: String?, newValue: String?, source: String = "unknown") {
        log(
            AuditSeverity.WARNING,
            AuditCategory.SYSTEM_PROPERTY_MODIFIED,
            "System property modified: $property",
            mapOf(
                "property" to property,
                "oldValue" to (oldValue ?: "null"),
                "newValue" to (newValue ?: "null"),
                "source" to source
            )
        )
    }
    
    // Enhanced Network & Radio Logging
    
    fun logBasebandVulnerabilityFound(cveId: String, severity: String, chipset: String, description: String) {
        log(
            if (severity.contains("CRITICAL", true)) AuditSeverity.CRITICAL else AuditSeverity.WARNING,
            AuditCategory.BASEBAND_VULNERABILITY_FOUND,
            "Baseband vulnerability detected: $cveId",
            mapOf(
                "cveId" to cveId,
                "severity" to severity,
                "chipset" to chipset,
                "description" to description.take(200)
            )
        )
    }
    
    fun logCellTowerAnomaly(cellId: String, anomalyType: String, expectedValue: Any?, actualValue: Any?, location: String? = null) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.CELL_TOWER_ANOMALY_DETECTED,
            "Cell tower anomaly detected: $anomalyType",
            mapOf(
                "cellId" to cellId,
                "anomalyType" to anomalyType,
                "expectedValue" to (expectedValue?.toString() ?: "null"),
                "actualValue" to (actualValue?.toString() ?: "null"),
                "location" to (location ?: "unknown")
            )
        )
    }
    
    fun logHandoverFailure(sourceCell: String, targetCell: String, failureReason: String, networkType: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.HANDOVER_FAILURE,
            "Handover failed: $sourceCell -> $targetCell",
            mapOf(
                "sourceCell" to sourceCell,
                "targetCell" to targetCell,
                "failureReason" to failureReason,
                "networkType" to networkType
            )
        )
    }
    
    // 5G/SA Specific Logging
    
    fun logNrStandaloneDetected(band: String, cellId: String, features: List<String> = emptyList()) {
        log(
            AuditSeverity.INFO,
            AuditCategory.NR_STANDALONE_DETECTED,
            "5G Standalone connection detected",
            mapOf(
                "band" to band,
                "cellId" to cellId,
                "features" to features.joinToString(","),
                "isMmWave" to band.startsWith("n26")
            )
        )
    }
    
    fun logDualConnectivityEstablished(lteCell: String, nrCell: String, configuration: String) {
        log(
            AuditSeverity.INFO,
            AuditCategory.DUAL_CONNECTIVITY_ESTABLISHED,
            "Dual connectivity (EN-DC) established",
            mapOf(
                "lteCell" to lteCell,
                "nrCell" to nrCell,
                "configuration" to configuration
            )
        )
    }
    
    // Performance & System Logging
    
    fun logMemoryThresholdExceeded(currentUsage: Long, threshold: Long, processName: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.MEMORY_THRESHOLD_EXCEEDED,
            "Memory threshold exceeded in $processName",
            mapOf(
                "currentUsageMB" to (currentUsage / 1024 / 1024),
                "thresholdMB" to (threshold / 1024 / 1024),
                "processName" to processName,
                "usagePercentage" to ((currentUsage.toDouble() / threshold) * 100)
            )
        )
    }
    
    fun logDatabaseOperationFailed(operation: String, table: String, errorCode: String, details: String) {
        log(
            AuditSeverity.ERROR,
            AuditCategory.DATABASE_OPERATION_FAILED,
            "Database operation failed: $operation on $table",
            mapOf(
                "operation" to operation,
                "table" to table,
                "errorCode" to errorCode,
                "details" to details.take(200)
            )
        )
    }
    
    // Panic & Recovery Logging
    
    fun logPanicModeActivated(trigger: String, duration: Long?, measures: List<String>) {
        log(
            AuditSeverity.CRITICAL,
            AuditCategory.PANIC_MODE_ACTIVATED,
            "Panic mode activated: $trigger",
            mapOf(
                "trigger" to trigger,
                "durationSeconds" to (duration ?: -1),
                "measures" to measures.joinToString(","),
                "timestamp" to System.currentTimeMillis()
            )
        )
    }
    
    fun logSystemRecoveryInitiated(recoveryType: String, success: Boolean, details: String) {
        log(
            if (success) AuditSeverity.INFO else AuditSeverity.ERROR,
            AuditCategory.SYSTEM_RECOVERY_INITIATED,
            "System recovery $recoveryType: ${if (success) "SUCCESS" else "FAILED"}",
            mapOf(
                "recoveryType" to recoveryType,
                "success" to success,
                "details" to details,
                "timestamp" to System.currentTimeMillis()
            )
        )
    }
    
    // Blocking & Mitigation Logging
    
    fun logGsmConnectionBlocked(cellId: String, reason: String, simSlot: Int, action: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.GSM_CONNECTION_BLOCKED,
            "GSM connection blocked: $reason",
            mapOf(
                "cellId" to cellId,
                "reason" to reason,
                "simSlot" to simSlot,
                "action" to action,
                "timestamp" to System.currentTimeMillis()
            )
        )
    }
    
    fun logCellTowerBlocked(cellId: String, blockReason: String, isTemporary: Boolean, duration: Long?) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.CELL_TOWER_BLOCKED,
            "Cell tower blocked: $cellId",
            mapOf(
                "cellId" to cellId,
                "blockReason" to blockReason,
                "isTemporary" to isTemporary,
                "durationSeconds" to (duration ?: -1),
                "timestamp" to System.currentTimeMillis()
            )
        )
    }
    
    fun logAutomatedResponseExecuted(responseType: String, trigger: String, success: Boolean, impact: String) {
        log(
            if (success) AuditSeverity.INFO else AuditSeverity.WARNING,
            AuditCategory.AUTOMATED_RESPONSE_EXECUTED,
            "Automated response executed: $responseType",
            mapOf(
                "responseType" to responseType,
                "trigger" to trigger,
                "success" to success,
                "impact" to impact,
                "timestamp" to System.currentTimeMillis()
            )
        )
    }

    fun logApiCallBlocked(url: String, reason: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.API_CALL_BLOCKED,
            "API call blocked: $reason",
            mapOf("url" to url, "reason" to reason)
        )
    }

    fun logCertificatePinVerificationFailed(domain: String) {
        log(
            AuditSeverity.CRITICAL,
            AuditCategory.CERTIFICATE_PIN_VERIFICATION_FAILED,
            "Certificate pinning verification failed for domain: $domain",
            mapOf("domain" to domain)
        )
    }

    fun logUnauthorizedAccessAttempt(source: String, action: String) {
        log(
            AuditSeverity.CRITICAL,
            AuditCategory.UNAUTHORIZED_ACCESS_ATTEMPT,
            "Unauthorized access attempt detected",
            mapOf("source" to source, "action" to action)
        )
    }

    fun logBroadcastSignatureVerificationFailed(action: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.BROADCAST_SIGNATURE_VERIFICATION_FAILED,
            "Broadcast signature verification failed for action: $action",
            mapOf("action" to action)
        )
    }

    fun logRegexTimeout(pattern: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.REGEX_TIMEOUT,
            "Regex matching timeout",
            mapOf("patternLength" to pattern.length)
        )
    }

    fun logProcessTimeout(command: String) {
        log(
            AuditSeverity.WARNING,
            AuditCategory.PROCESS_TIMEOUT,
            "Process execution timeout",
            mapOf("command" to command)
        )
    }

    fun logImsiCatcherDetected(severity: Int, details: String, simSlot: Int) {
        log(
            if (severity >= 9) AuditSeverity.CRITICAL else AuditSeverity.WARNING,
            AuditCategory.IMSI_CATCHER_DETECTED,
            "IMSI Catcher detected: $details",
            mapOf("severity" to severity, "simSlot" to simSlot)
        )
    }

    fun logCipheringOffDetected(simSlot: Int) {
        log(
            AuditSeverity.CRITICAL,
            AuditCategory.CIPHERING_OFF_DETECTED,
            "Unencrypted connection (A5/0) detected",
            mapOf("simSlot" to simSlot)
        )
    }

    fun logSecuritySettingChanged(setting: String, oldValue: Any?, newValue: Any?) {
        log(
            AuditSeverity.INFO,
            AuditCategory.SECURITY_SETTING_CHANGED,
            "Security setting changed: $setting",
            mapOf(
                "setting" to setting,
                "oldValue" to (oldValue?.toString() ?: "null"),
                "newValue" to (newValue?.toString() ?: "null")
            )
        )
    }

    fun getAuditLog(): List<AuditEntry> {
        return auditQueue.toList()
    }

    fun getAuditLogFiltered(severity: AuditSeverity? = null, category: AuditCategory? = null, limit: Int = 1000): List<AuditEntry> {
        var filtered = auditQueue.toList()
        
        severity?.let { s ->
            filtered = filtered.filter { it.severity == s }
        }
        
        category?.let { c ->
            filtered = filtered.filter { it.category == c }
        }
        
        return filtered.sortedByDescending { it.timestamp }.take(limit)
    }

    fun getCriticalEvents(): List<AuditEntry> {
        return auditQueue.filter { it.severity == AuditSeverity.CRITICAL }
            .sortedByDescending { it.timestamp }
    }

    fun getSecurityEvents(): List<AuditEntry> {
        val securityCategories = setOf(
            AuditCategory.ROOT_ACCESS_DETECTED,
            AuditCategory.UNAUTHORIZED_ACCESS_ATTEMPT,
            AuditCategory.CERTIFICATE_PIN_VERIFICATION_FAILED,
            AuditCategory.IMSI_CATCHER_DETECTED,
            AuditCategory.CIPHERING_OFF_DETECTED,
            AuditCategory.SILENT_SMS_DETECTED,
            AuditCategory.NETWORK_DOWNGRADE_DETECTED
        )
        return auditQueue.filter { it.category in securityCategories }
            .sortedByDescending { it.timestamp }
    }

    fun getPerformanceEvents(): List<AuditEntry> {
        val performanceCategories = setOf(
            AuditCategory.MEMORY_THRESHOLD_EXCEEDED,
            AuditCategory.CPU_THRESHOLD_EXCEEDED,
            AuditCategory.DATABASE_OPERATION_FAILED,
            AuditCategory.CACHE_OVERFLOW,
            AuditCategory.REGEX_TIMEOUT,
            AuditCategory.PROCESS_TIMEOUT,
            AuditCategory.API_TIMEOUT
        )
        return auditQueue.filter { it.category in performanceCategories }
            .sortedByDescending { it.timestamp }
    }

    fun getAuditLogAsString(): String {
        return auditQueue.joinToString("\n") { formatLogMessage(it) }
    }

    fun clearAuditLog() {
        auditQueue.clear()
    }

    fun getAuditStatistics(): String {
        val entries = auditQueue.toList()
        val bySeverity = entries.groupingBy { it.severity }.eachCount()
        val byCategory = entries.groupingBy { it.category }.eachCount()
        val last24h = entries.filter { System.currentTimeMillis() - it.timestamp < 24 * 60 * 60 * 1000 }
        val last1h = entries.filter { System.currentTimeMillis() - it.timestamp < 60 * 60 * 1000 }
        
        val criticalCount = bySeverity[AuditSeverity.CRITICAL] ?: 0
        val errorCount = bySeverity[AuditSeverity.ERROR] ?: 0
        val warningCount = bySeverity[AuditSeverity.WARNING] ?: 0
        
        val topCategories = byCategory.entries
            .sortedByDescending { it.value }
            .take(10)
        
        val recentCritical = last24h.filter { it.severity == AuditSeverity.CRITICAL }.size
        val recentErrors = last24h.filter { it.severity == AuditSeverity.ERROR }.size

        return """
            ╔══════════════════════════════════════════════════╗
            ║           SECURITY AUDIT LOG STATISTICS           ║
            ╠══════════════════════════════════════════════════╣
            ║ Total Entries: ${"%6d".format(entries.size)}
            ║ Last 24 Hours: ${"%6d".format(last24h.size)}
            ║ Last Hour:     ${"%6d".format(last1h.size)}
            ╠══════════════════════════════════════════════════╣
            ║ Severity Distribution:
            ║   CRITICAL: ${"%4d".format(criticalCount)} (${"%3.1f".format(if (entries.isNotEmpty()) criticalCount * 100.0 / entries.size else 0.0)}%)
            ║   ERROR:    ${"%4d".format(errorCount)} (${"%3.1f".format(if (entries.isNotEmpty()) errorCount * 100.0 / entries.size else 0.0)}%)
            ║   WARNING:  ${"%4d".format(warningCount)} (${"%3.1f".format(if (entries.isNotEmpty()) warningCount * 100.0 / entries.size else 0.0)}%)
            ║   INFO:     ${"%4d".format(bySeverity[AuditSeverity.INFO] ?: 0)} (${"%3.1f".format(if (entries.isNotEmpty()) (bySeverity[AuditSeverity.INFO] ?: 0) * 100.0 / entries.size else 0.0)}%)
            ╠══════════════════════════════════════════════════╣
            ║ Recent Critical Events (24h): ${"%3d".format(recentCritical)}
            ║ Recent Error Events (24h):    ${"%3d".format(recentErrors)}
            ╠══════════════════════════════════════════════════╣
            ║ Top Categories:
            ${topCategories.joinToString("\n") { "║   - ${"%-25s".format(it.key.name.take(25))}: ${"%4d".format(it.value)}" }}
            ╠══════════════════════════════════════════════════╣
            ║ Queue Status: ${auditQueue.size}/${MAX_QUEUE_SIZE} (${"%3.1f".format(auditQueue.size * 100.0 / MAX_QUEUE_SIZE)}% full)
            ║ Memory Usage: ~${(auditQueue.size * 200 / 1024)}KB estimated
            ╚══════════════════════════════════════════════════╝
        """.trimIndent()
    }
    
    fun exportAuditLog(): String {
        val entries = auditQueue.toList().sortedByDescending { it.timestamp }
        val header = """
            # Sentry Radio Security Audit Log Export
            # Generated: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}
            # Total Entries: ${entries.size}
            # Format: [Timestamp] [Severity] [Category] Message | Details
            # 
        """.trimIndent()
        
        val logEntries = entries.joinToString("\n") { entry ->
            val timestamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.US).format(Date(entry.timestamp))
            val detailsStr = if (entry.details.isNotEmpty()) {
                " | ${entry.details.entries.joinToString(", ") { "${it.key}=${it.value}" }}"
            } else {
                ""
            }
            val stackTraceStr = if (entry.stackTrace != null) {
                "\n  StackTrace: ${entry.stackTrace.replace("\n", "\n    ")}"
            } else {
                ""
            }
            "[$timestamp] [${entry.severity}] [${entry.category}] ${entry.message}$detailsStr$stackTraceStr"
        }
        
        return header + "\n\n" + logEntries
    }
    
    fun getHealthStatus(): AuditHealthStatus {
        val entries = auditQueue.toList()
        val last1h = entries.filter { System.currentTimeMillis() - it.timestamp < 60 * 60 * 1000 }
        val criticalCount = last1h.filter { it.severity == AuditSeverity.CRITICAL }.size
        val errorCount = last1h.filter { it.severity == AuditSeverity.ERROR }.size
        
        val status = when {
            criticalCount > 0 -> HealthLevel.CRITICAL
            errorCount > 5 -> HealthLevel.WARNING
            errorCount > 0 -> HealthLevel.CAUTION
            else -> HealthLevel.HEALTHY
        }
        
        return AuditHealthStatus(
            status = status,
            criticalEvents = criticalCount,
            errorEvents = errorCount,
            totalEvents = last1h.size,
            queueUtilization = auditQueue.size * 100.0 / MAX_QUEUE_SIZE,
            lastCriticalEvent = entries.filter { it.severity == AuditSeverity.CRITICAL }
                .maxByOrNull { it.timestamp }?.timestamp
        )
    }
    
    data class AuditHealthStatus(
        val status: HealthLevel,
        val criticalEvents: Int,
        val errorEvents: Int,
        val totalEvents: Int,
        val queueUtilization: Double,
        val lastCriticalEvent: Long?
    )
    
    enum class HealthLevel {
        HEALTHY, CAUTION, WARNING, CRITICAL
    }

    private fun formatLogMessage(entry: AuditEntry): String {
        val timestamp = dateFormat.format(Date(entry.timestamp))
        val detailsStr = if (entry.details.isNotEmpty()) {
            " | ${entry.details.entries.joinToString(", ") { "${it.key}=${it.value}" }}"
        } else {
            ""
        }
        return "[$timestamp] [${entry.severity}] [${entry.category}] ${entry.message}$detailsStr"
    }

    private fun formatStackTrace(throwable: Throwable): String {
        val sw = java.io.StringWriter()
        throwable.printStackTrace(java.io.PrintWriter(sw))
        return sw.toString().take(500) // Limit to 500 chars
    }
}
