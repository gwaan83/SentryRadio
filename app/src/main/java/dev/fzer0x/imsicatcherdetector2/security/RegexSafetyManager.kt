package dev.fzer0x.imsicatcherdetector2.security

import android.util.Log
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.regex.PatternSyntaxException

object RegexSafetyManager {
    private val TAG = "RegexSafety"
    
    // Centralized timeout configuration
    private val DEFAULT_TIMEOUT_MS = 100L
    private val MAX_TIMEOUT_MS = 5000L
    private val threadPool = java.util.concurrent.Executors.newCachedThreadPool { r ->
        Thread(r, "RegexSafety-${Thread.currentThread().id}").apply {
            isDaemon = true
            priority = Thread.MIN_PRIORITY
        }
    }
    
    // Thread-safe regex pattern cache
    private val patternCache = ConcurrentHashMap<String, java.util.regex.Pattern>()
    private val MAX_CACHE_SIZE = 100

    fun safeRegexMatch(pattern: String, input: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): Boolean {
        val actualTimeout = timeoutMs.coerceIn(1, MAX_TIMEOUT_MS)
        
        return try {
            // Get or create compiled pattern from cache
            val compiledPattern = patternCache.getOrPut(pattern) {
                if (patternCache.size >= MAX_CACHE_SIZE) {
                    // Simple cache eviction - remove oldest entries
                    val keysToRemove = patternCache.keys.take(10)
                    keysToRemove.forEach { key -> patternCache.remove(key) }
                }
                java.util.regex.Pattern.compile(pattern)
            }

            // Execute match with timeout using thread pool
            val future = threadPool.submit<Boolean> {
                try {
                    compiledPattern.matcher(input).find()
                } catch (e: Exception) {
                    Log.w(TAG, "Regex match error: ${e.message}")
                    false
                }
            }

            try {
                future.get(actualTimeout, TimeUnit.MILLISECONDS)
            } catch (e: java.util.concurrent.TimeoutException) {
                future.cancel(true)
                Log.w(TAG, "Regex match timeout for pattern: ${pattern.take(50)}")
                false
            } catch (e: Exception) {
                Log.e(TAG, "Regex execution error: ${e.message}")
                false
            }
        } catch (e: PatternSyntaxException) {
            Log.w(TAG, "Invalid regex pattern: ${e.message}")
            false
        } catch (e: Exception) {
            Log.e(TAG, "Regex error: ${e.message}")
            false
        }
    }

    fun safeRegexExtract(pattern: String, input: String, group: Int = 1, timeoutMs: Long = DEFAULT_TIMEOUT_MS): String? {
        val actualTimeout = timeoutMs.coerceIn(1, MAX_TIMEOUT_MS)
        
        return try {
            val compiledPattern = patternCache.getOrPut(pattern) {
                if (patternCache.size >= MAX_CACHE_SIZE) {
                    val keysToRemove = patternCache.keys.take(10)
                    keysToRemove.forEach { key -> patternCache.remove(key) }
                }
                java.util.regex.Pattern.compile(pattern)
            }

            val future = threadPool.submit<String?> {
                try {
                    val matcher = compiledPattern.matcher(input)
                    if (matcher.find() && group <= matcher.groupCount()) {
                        matcher.group(group)
                    } else null
                } catch (e: Exception) {
                    Log.w(TAG, "Regex extract error: ${e.message}")
                    null
                }
            }

            try {
                future.get(actualTimeout, TimeUnit.MILLISECONDS)
            } catch (e: java.util.concurrent.TimeoutException) {
                future.cancel(true)
                Log.w(TAG, "Regex extract timeout")
                null
            } catch (e: Exception) {
                Log.e(TAG, "Regex extract error: ${e.message}")
                null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Regex extract error: ${e.message}")
            null
        }
    }

    fun sanitizeForRegex(input: String): String {
        return java.util.regex.Pattern.quote(input)
    }
    
    /**
     * Clear pattern cache and shutdown thread pool
     */
    fun cleanup() {
        patternCache.clear()
        threadPool.shutdown()
        try {
            if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) {
                threadPool.shutdownNow()
            }
        } catch (e: InterruptedException) {
            threadPool.shutdownNow()
            Thread.currentThread().interrupt()
        }
    }
}
