package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import com.topjohnwu.superuser.Shell
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/**
 * Dedizierter Root-Repository für eine stabile Shell-Interaktion.
 * Nutzt libsu für persistente Shell-Sessions, was Akku und CPU spart.
 */
object RootRepository {
    private const val TAG = "RootRepository"

    init {
        // Globale Konfiguration für libsu
        Shell.setDefaultBuilder(Shell.Builder.create()
            .setFlags(Shell.FLAG_REDIRECT_STDERR)
            .setTimeout(10))
    }

    /**
     * Prüft, ob Root-Zugriff gewährt wurde.
     * Verbessert: Führt einen echten Test-Befehl aus.
     */
    suspend fun isRootAvailable(): Boolean = withContext(Dispatchers.IO) {
        try {
            // Manchmal liefert isRoot ein falsches Negativ, wenn die Shell noch nicht bereit ist.
            // Wir erzwingen eine Prüfung.
            Shell.getShell().isRoot || Shell.cmd("id").exec().isSuccess
        } catch (e: Exception) {
            Log.e(TAG, "Root check failed", e)
            false
        }
    }

    /**
     * Führt einen Befehl als Root aus und gibt das Ergebnis zurück.
     * Nutzt die globale Shell-Instanz von libsu (hält die Session offen).
     */
    suspend fun execute(command: String): ShellResult = withContext(Dispatchers.IO) {
        return@withContext try {
            val result = Shell.cmd(command).exec()
            ShellResult(
                success = result.isSuccess,
                output = result.out.joinToString("\n"),
                error = result.err.joinToString("\n"),
                exitCode = result.code
            )
        } catch (e: Exception) {
            Log.e(TAG, "Root command failed: $command", e)
            ShellResult(
                success = false,
                output = "",
                error = "Execution failed: ${e.message}",
                exitCode = -1
            )
        }
    }

    /**
     * Führt einen Root-Befehl mit Retry-Mechanismus aus
     */
    suspend fun executeWithRetry(
        command: String, 
        maxRetries: Int = 3,
        retryDelayMs: Long = 1000
    ): ShellResult = withContext(Dispatchers.IO) {
        var lastResult: ShellResult? = null
        
        repeat(maxRetries) { attempt ->
            try {
                val result = execute(command)
                if (result.success) {
                    return@withContext result
                }
                lastResult = result
                
                if (attempt < maxRetries - 1) {
                    Log.w(TAG, "Command failed (attempt ${attempt + 1}/$maxRetries): $command")
                    delay(retryDelayMs * (attempt + 1)) // Exponential backoff
                }
            } catch (e: Exception) {
                Log.e(TAG, "Command execution failed (attempt ${attempt + 1}/$maxRetries)", e)
                if (attempt < maxRetries - 1) {
                    delay(retryDelayMs * (attempt + 1))
                }
            }
        }
        
        lastResult ?: ShellResult(false, "", "All retries failed", -1)
    }

    /**
     * Prüft die Existenz einer Datei oder eines Verzeichnisses als Root.
     */
    suspend fun fileExists(path: String): Boolean = withContext(Dispatchers.IO) {
        Shell.cmd("[ -f \"$path\" ] || [ -d \"$path\" ]").exec().isSuccess
    }

    data class ShellResult(
        val success: Boolean,
        val output: String,
        val error: String,
        val exitCode: Int
    )
}
