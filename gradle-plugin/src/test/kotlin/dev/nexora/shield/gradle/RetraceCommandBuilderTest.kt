package dev.nexora.shield.gradle

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import kotlin.io.path.createFile
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class RetraceCommandBuilderTest {
    @TempDir
    lateinit var tempDir: Path

    @Test
    fun buildsArgumentVectorWithoutShellInterpolation() {
        val mapping = tempDir.resolve("mapping with spaces.txt").createFile().toFile()
        val stack = tempDir.resolve("stack trace.txt").createFile().toFile()

        val command = RetraceCommandBuilder.build("retrace", mapping, stack)

        assertEquals(
            listOf("retrace", mapping.absolutePath, stack.absolutePath),
            command,
        )
    }

    @Test
    fun missingMappingFailsClosed() {
        val mapping = tempDir.resolve("missing.txt").toFile()
        val stack = tempDir.resolve("stack.txt").createFile().toFile()

        assertFailsWith<IllegalArgumentException> {
            RetraceCommandBuilder.build("retrace", mapping, stack)
        }
    }

    @Test
    fun blankExecutableFailsClosed() {
        val mapping = tempDir.resolve("mapping.txt").createFile().toFile()
        val stack = tempDir.resolve("stack.txt").createFile().toFile()

        assertFailsWith<IllegalArgumentException> {
            RetraceCommandBuilder.build(" ", mapping, stack)
        }
    }
}
