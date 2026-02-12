package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import java.io.BufferedReader
import java.io.InputStream
import java.util.concurrent.TimeUnit
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

object ProcessSafetyManager {
    private val TAG = "ProcessSafety"
    private const val PROCESS_TIMEOUT_SEC = 5L
    private val MAX_CONCURRENT_PROCESSES = 10
    private val activeProcesses = ConcurrentHashMap<String, Process>()
    private val processCounter = AtomicInteger(0)

    data class ProcessResult(
        val success: Boolean,
        val output: String,
        val error: String? = null
    )

    fun executeCommandWithTimeout(
        command: Array<String>,
        timeoutSec: Long = PROCESS_TIMEOUT_SEC
    ): ProcessResult {
        val processId = "proc_${processCounter.incrementAndGet()}"
        
        // Check concurrent process limit
        if (activeProcesses.size >= MAX_CONCURRENT_PROCESSES) {
            Log.w(TAG, "Too many concurrent processes, rejecting new command")
            return ProcessResult(false, "", "Process limit exceeded")
        }
        
        var process: Process? = null
        
        return try {
            process = Runtime.getRuntime().exec(command)
            activeProcesses[processId] = process

            // Create threads to read output and error streams
            val outputBuilder = StringBuilder()
            val errorBuilder = StringBuilder()

            val outputThread = Thread {
                try {
                    BufferedReader(process.inputStream.reader()).use { reader ->
                        reader.forEachLine { outputBuilder.append(it).append("\n") }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Error reading process output: ${e.message}")
                }
            }

            val errorThread = Thread {
                try {
                    BufferedReader(process.errorStream.reader()).use { reader ->
                        reader.forEachLine { errorBuilder.append(it).append("\n") }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Error reading process error: ${e.message}")
                }
            }

            outputThread.start()
            errorThread.start()

            // Wait for process with timeout
            val completed = process.waitFor(timeoutSec, TimeUnit.SECONDS)

            if (!completed) {
                Log.w(TAG, "Process timeout after ${timeoutSec}s for command: ${command.joinToString(" ")}")
                destroyProcessSafely(process)
                outputThread.interrupt()
                errorThread.interrupt()
                return ProcessResult(false, "", "Process timeout")
            }

            outputThread.join(1000)
            errorThread.join(1000)

            val exitCode = process.exitValue()
            if (exitCode != 0) {
                Log.w(TAG, "Process exited with code $exitCode")
                return ProcessResult(false, outputBuilder.toString(), errorBuilder.toString())
            }

            ProcessResult(true, outputBuilder.toString())
        } catch (e: Exception) {
            Log.e(TAG, "Error executing command: ${e.message}")
            ProcessResult(false, "", e.message)
        } finally {
            // Cleanup
            activeProcesses.remove(processId)
            destroyProcessSafely(process)
        }
    }

    fun closeStreamSafely(stream: InputStream?) {
        try {
            stream?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing stream: ${e.message}")
        }
    }

    fun destroyProcessSafely(process: Process?) {
        try {
            process?.inputStream?.close()
            process?.outputStream?.close()
            process?.errorStream?.close()
            process?.destroyForcibly()
        } catch (e: Exception) {
            Log.w(TAG, "Error destroying process: ${e.message}")
        }
    }
    
    /**
     * Force cleanup of all active processes
     */
    fun forceCleanupAllProcesses() {
        Log.w(TAG, "Force cleaning up ${activeProcesses.size} active processes")
        activeProcesses.values.forEach { process ->
            destroyProcessSafely(process)
        }
        activeProcesses.clear()
    }
    
    /**
     * Get current process statistics
     */
    fun getProcessStats(): ProcessStats {
        return ProcessStats(
            activeProcessCount = activeProcesses.size,
            maxConcurrentProcesses = MAX_CONCURRENT_PROCESSES,
            totalProcessesCreated = processCounter.get()
        )
    }
}

data class ProcessStats(
    val activeProcessCount: Int,
    val maxConcurrentProcesses: Int,
    val totalProcessesCreated: Int
)
