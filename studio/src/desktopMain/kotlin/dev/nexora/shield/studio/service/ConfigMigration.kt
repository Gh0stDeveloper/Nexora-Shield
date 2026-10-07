package dev.nexora.shield.studio.service

data class ConfigMigrationResult(
    val root: LinkedHashMap<String, Any?>,
    val sourceSchema: Int,
    val targetSchema: Int,
    val changed: Boolean,
)

object ConfigMigration {
    const val CURRENT_SCHEMA = 1

    fun migrate(source: LinkedHashMap<String, Any?>): ConfigMigrationResult {
        val root = deepCopy(source)
        val declared = number(root["schema"])?.toInt()

        if (declared != null && declared > CURRENT_SCHEMA) {
            error("Configuration schema $declared is newer than Studio supports.")
        }

        if (declared == CURRENT_SCHEMA) {
            return ConfigMigrationResult(root, CURRENT_SCHEMA, CURRENT_SCHEMA, false)
        }

        if (root["application"] is Map<*, *>) {
            root["schema"] = CURRENT_SCHEMA
            return ConfigMigrationResult(
                root = root,
                sourceSchema = declared ?: 0,
                targetSchema = CURRENT_SCHEMA,
                changed = true,
            )
        }

        val applicationId = root.remove("applicationId")?.toString()
            ?: error("Legacy configuration requires applicationId.")
        val minSdk = number(root.remove("minSdk"))?.toInt()
            ?: error("Legacy configuration requires minSdk.")
        val profile = root.remove("protectionProfile") ?: root["profile"] ?: "hardened"

        root["schema"] = CURRENT_SCHEMA
        root["application"] = linkedMapOf(
            "id" to applicationId,
            "minSdk" to minSdk,
        )
        root["profile"] = profile

        return ConfigMigrationResult(
            root = root,
            sourceSchema = declared ?: 0,
            targetSchema = CURRENT_SCHEMA,
            changed = true,
        )
    }

    private fun deepCopy(source: Map<String, Any?>): LinkedHashMap<String, Any?> =
        linkedMapOf<String, Any?>().also { target ->
            source.forEach { (key, value) ->
                target[key] = when (value) {
                    is Map<*, *> -> {
                        val mapped = linkedMapOf<String, Any?>()
                        value.forEach { (childKey, childValue) ->
                            if (childKey is String) mapped[childKey] = childValue
                        }
                        deepCopy(mapped)
                    }
                    is List<*> -> value.toList()
                    else -> value
                }
            }
        }

    private fun number(value: Any?): Number? = when (value) {
        is Number -> value
        is String -> value.toDoubleOrNull()
        else -> null
    }
}
