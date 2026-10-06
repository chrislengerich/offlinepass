package com.linuxpass.app.vault

import java.io.File
import java.io.RandomAccessFile

/**
 * Best-effort secure erasure for plaintext temp files: the contents are
 * overwritten with zeros in place BEFORE the file is unlinked, so the bytes
 * don't survive as a recoverable "deleted" file in the cache dir. (Flash
 * wear-leveling makes any in-place overwrite best-effort; the real defense
 * is that plaintext lives in app-private storage for seconds, not minutes.)
 */
object SecureWipe {
    private const val CHUNK = 64 * 1024

    /** Overwrites [file] with zeros, then deletes it. Missing files are a no-op. */
    fun file(file: File?) {
        if (file == null || !file.exists()) return
        try {
            RandomAccessFile(file, "rw").use { raf ->
                val len = raf.length()
                val zeros = ByteArray(CHUNK)
                var pos = 0L
                while (pos < len) {
                    val n = minOf(CHUNK.toLong(), len - pos).toInt()
                    raf.write(zeros, 0, n)
                    pos += n
                }
            }
        } catch (_: Exception) {
            // Unwritable or already gone: fall through to the delete.
        }
        // Unlink regardless — an un-zeroed leftover is still worse than none.
        file.delete()
    }

    fun all(vararg files: File?) = files.forEach { file(it) }
}
