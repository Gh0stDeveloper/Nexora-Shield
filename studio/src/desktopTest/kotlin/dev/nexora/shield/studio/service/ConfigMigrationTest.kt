package dev.nexora.shield.studio.service

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ConfigMigrationTest {
    @Test
    fun legacyFlatConfigMigratesToSchemaOne() {
        val source = linkedMapOf<String, Any?>(
            "applicationId" to "dev.nexora.sample",
            "minSdk" to 24,
            "protectionProfile" to "hardened",
            "dex" to linkedMapOf("rename" to true),
        )

        val migrated = ConfigMigration.migrate(source)

        assertTrue(migrated.changed)
        assertEquals(0, migrated.sourceSchema)
        assertEquals(1, migrated.targetSchema)
        assertEquals(1, migrated.root["schema"])
        val application = migrated.root["application"] as Map<*, *>
        assertEquals("dev.nexora.sample", application["id"])
        assertEquals(24, application["minSdk"])
        assertEquals("hardened", migrated.root["profile"])
        assertTrue(migrated.root.containsKey("dex"))
    }

    @Test
    fun currentSchemaIsNoOp() {
        val source = linkedMapOf<String, Any?>(
            "schema" to 1,
            "application" to linkedMapOf(
                "id" to "dev.nexora.sample",
                "minSdk" to 24,
            ),
            "profile" to "standard",
        )

        val migrated = ConfigMigration.migrate(source)

        assertTrue(!migrated.changed)
        assertEquals(1, migrated.sourceSchema)
        assertEquals(source, migrated.root)
    }

    @Test
    fun futureSchemaFailsClosed() {
        val source = linkedMapOf<String, Any?>("schema" to 2)
        assertFailsWith<IllegalStateException> {
            ConfigMigration.migrate(source)
        }
    }
}
