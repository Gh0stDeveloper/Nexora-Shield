package dev.nexora.shield.gradle

import org.gradle.api.GradleException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.io.File

class SecretResolverTest {
    @TempDir
    lateinit var tempDir: File

    @Test
    fun resolvesEnvironmentReference() {
        val value = SecretResolver.resolve(
            "env:NEXORA_TEST_SECRET",
            tempDir,
            mapOf("NEXORA_TEST_SECRET" to "correct-horse-battery-staple"),
        )
        assertEquals("correct-horse-battery-staple", value)
    }

    @Test
    fun resolvesRelativeSecretFileAndOnlyTrimsLineEnding() {
        File(tempDir, "store.pass").writeText("  value with spaces  \n")
        val value = SecretResolver.resolve("file:store.pass", tempDir, emptyMap())
        assertEquals("  value with spaces  ", value)
    }

    @Test
    fun rejectsUnknownSecretProviders() {
        assertThrows(GradleException::class.java) {
            SecretResolver.resolve("plain:secret", tempDir, emptyMap())
        }
    }

    @Test
    fun rejectsMissingEnvironmentSecret() {
        assertThrows(GradleException::class.java) {
            SecretResolver.resolve("env:MISSING", tempDir, emptyMap())
        }
    }
}
