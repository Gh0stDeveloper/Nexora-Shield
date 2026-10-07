package dev.nexora.shield.gradle

import org.gradle.testfixtures.ProjectBuilder
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class NexoraShieldExtensionTest {
    @Test
    fun releaseOnlyAndSafeDefaultsAreStrict() {
        val project = ProjectBuilder.builder().build()
        val extension = project.objects.newInstance(NexoraShieldExtension::class.java)

        assertTrue(extension.enabled.get())
        assertTrue(extension.releaseOnly.get())
        assertEquals("hardened", extension.profile.get())
        assertEquals("nexora-shield", extension.cliExecutable.get())
        assertFalse(extension.allowUnsigned.get())
        assertTrue(extension.align.get())
        assertEquals(24, extension.minSdk.get())
        assertTrue(extension.publicReports.get())
        assertFalse(extension.privateReports.get())
        assertTrue(extension.preserveMapping.get())
        assertFalse(extension.buildCacheEnabled.get())
    }
}
