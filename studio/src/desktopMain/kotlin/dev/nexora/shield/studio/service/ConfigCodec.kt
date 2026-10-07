package dev.nexora.shield.studio.service

import dev.nexora.shield.studio.model.BudgetPolicy
import dev.nexora.shield.studio.model.ConfigDocument
import dev.nexora.shield.studio.model.PerformanceBudgets
import dev.nexora.shield.studio.model.SecretSettings
import dev.nexora.shield.studio.model.SelectorGroup
import dev.nexora.shield.studio.model.ShieldProfile
import dev.nexora.shield.studio.model.StudioConfig
import org.snakeyaml.engine.v2.api.Dump
import org.snakeyaml.engine.v2.api.DumpSettings
import org.snakeyaml.engine.v2.api.Load
import org.snakeyaml.engine.v2.api.LoadSettings
import org.snakeyaml.engine.v2.common.FlowStyle
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import kotlin.io.path.exists

class ConfigCodec {
    fun load(path: Path): ConfigDocument {
        if (!path.exists()) {
            val config = StudioConfig()
            return ConfigDocument(defaultRoot(config), config)
        }

        require(Files.size(path) <= MAX_CONFIG_BYTES) {
            "Configuration exceeds the Studio size limit."
        }

        val settings = LoadSettings.builder()
            .setLabel(path.fileName.toString())
            .build()
        val loaded = Load(settings).loadFromString(Files.readString(path))
        val loadedRoot = stringKeyMap(loaded)
        val root = ConfigMigration.migrate(loadedRoot).root
        val config = decode(root)
        validate(config)
        return ConfigDocument(root, config)
    }

    fun save(path: Path, document: ConfigDocument, config: StudioConfig): ConfigDocument {
        validate(config)
        val root = deepCopyMap(document.root)
        root["schema"] = 1

        val application = section(root, "application")
        application["id"] = config.applicationId.trim()
        application["minSdk"] = config.minSdk
        root["application"] = application

        root["profile"] = config.profile.wireValue

        val selectors = linkedMapOf<String, Any?>()
        config.selectors
            .map(::normalizeSelector)
            .filter { it.name.isNotBlank() }
            .forEach { selector ->
                selectors[selector.name] = linkedMapOf(
                    "include" to selector.include,
                    "exclude" to selector.exclude,
                )
            }
        root["selectors"] = selectors

        val budgets = section(root, "budgets")
        setOrRemove(budgets, "apkGrowthPercent", config.budgets.apkGrowthPercent)
        setOrRemove(budgets, "startupMs", config.budgets.startupMs)
        setOrRemove(budgets, "startupMsP50", config.budgets.startupMsP50)
        setOrRemove(budgets, "startupMsP95", config.budgets.startupMsP95)
        setOrRemove(budgets, "memoryMb", config.budgets.memoryMb)
        setOrRemove(budgets, "vmMethods", config.budgets.vmMethods)
        setOrRemove(budgets, "buildMinutes", config.budgets.buildMinutes)
        root["budgets"] = budgets
        root["budgetsPolicy"] = config.budgetPolicy.wireValue

        val secrets = section(root, "secrets")
        setStringOrRemove(secrets, "provider", config.secrets.provider)
        setStringOrRemove(secrets, "signingKeyRef", config.secrets.signingKeyRef)
        setStringOrRemove(secrets, "buildSeedRef", config.secrets.buildSeedRef)
        setStringOrRemove(secrets, "buildNonceRef", config.secrets.buildNonceRef)
        if (secrets.isEmpty()) {
            root.remove("secrets")
        } else {
            root["secrets"] = secrets
        }

        val dumpSettings = DumpSettings.builder()
            .setDefaultFlowStyle(FlowStyle.BLOCK)
            .setIndent(2)
            .build()
        val yaml = Dump(dumpSettings).dumpToString(root)

        path.parent?.let { Files.createDirectories(it) }
        val temporary = path.resolveSibling(path.fileName.toString() + ".studio.tmp")
        Files.writeString(temporary, yaml)
        try {
            Files.move(
                temporary,
                path,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (_: AtomicMoveNotSupportedException) {
            Files.move(temporary, path, StandardCopyOption.REPLACE_EXISTING)
        }

        return ConfigDocument(root, config)
    }

    fun validate(config: StudioConfig) {
        require(config.schema == 1) { "Studio supports configuration schema 1 only." }
        require(APPLICATION_ID.matches(config.applicationId.trim())) {
            "Application id must be a valid dotted Android application id."
        }
        require(config.minSdk >= 24) { "Nexora Shield requires minSdk >= 24." }

        val names = mutableSetOf<String>()
        config.selectors.forEach { selector ->
            require(selector.name.isNotBlank()) { "Selector names must not be blank." }
            require(names.add(selector.name.trim())) { "Selector names must be unique." }
        }

        val budgets = config.budgets
        listOf(
            budgets.apkGrowthPercent,
            budgets.startupMs,
            budgets.startupMsP50,
            budgets.startupMsP95,
            budgets.memoryMb,
            budgets.buildMinutes,
        ).filterNotNull().forEach { require(it >= 0.0) { "Performance budgets must be non-negative." } }
        budgets.vmMethods?.let { require(it >= 0) { "VM method budget must be non-negative." } }
    }

    private fun decode(root: LinkedHashMap<String, Any?>): StudioConfig {
        val schema = number(root["schema"])?.toInt() ?: 1
        val application = map(root["application"])
        val selectorsRoot = map(root["selectors"])
        val selectors = selectorsRoot.entries.map { (name, value) ->
            val selector = map(value)
            SelectorGroup(
                name = name,
                include = stringList(selector["include"]),
                exclude = stringList(selector["exclude"]),
            )
        }.sortedBy { it.name }

        val budgets = map(root["budgets"])
        val secrets = map(root["secrets"])

        return StudioConfig(
            schema = schema,
            applicationId = application["id"]?.toString() ?: "com.example.app",
            minSdk = number(application["minSdk"])?.toInt() ?: 24,
            profile = ShieldProfile.fromWire(root["profile"]?.toString()),
            selectors = selectors,
            budgets = PerformanceBudgets(
                apkGrowthPercent = number(budgets["apkGrowthPercent"])?.toDouble(),
                startupMs = number(budgets["startupMs"])?.toDouble(),
                startupMsP50 = number(budgets["startupMsP50"])?.toDouble(),
                startupMsP95 = number(budgets["startupMsP95"])?.toDouble(),
                memoryMb = number(budgets["memoryMb"])?.toDouble(),
                vmMethods = number(budgets["vmMethods"])?.toInt(),
                buildMinutes = number(budgets["buildMinutes"])?.toDouble(),
            ),
            budgetPolicy = BudgetPolicy.fromWire(root["budgetsPolicy"]?.toString()),
            secrets = SecretSettings(
                provider = secrets["provider"]?.toString(),
                signingKeyRef = secrets["signingKeyRef"]?.toString(),
                buildSeedRef = secrets["buildSeedRef"]?.toString(),
                buildNonceRef = secrets["buildNonceRef"]?.toString(),
            ),
        )
    }

    private fun defaultRoot(config: StudioConfig): LinkedHashMap<String, Any?> = linkedMapOf(
        "schema" to 1,
        "application" to linkedMapOf(
            "id" to config.applicationId,
            "minSdk" to config.minSdk,
        ),
        "profile" to config.profile.wireValue,
    )

    private fun normalizeSelector(selector: SelectorGroup): SelectorGroup = selector.copy(
        name = selector.name.trim(),
        include = selector.include.map(String::trim).filter(String::isNotEmpty).distinct(),
        exclude = selector.exclude.map(String::trim).filter(String::isNotEmpty).distinct(),
    )

    private fun section(root: MutableMap<String, Any?>, key: String): LinkedHashMap<String, Any?> =
        LinkedHashMap(map(root[key]))

    private fun setOrRemove(map: MutableMap<String, Any?>, key: String, value: Any?) {
        if (value == null) map.remove(key) else map[key] = value
    }

    private fun setStringOrRemove(map: MutableMap<String, Any?>, key: String, value: String?) {
        val normalized = value?.trim().orEmpty()
        if (normalized.isEmpty()) map.remove(key) else map[key] = normalized
    }

    private fun map(value: Any?): LinkedHashMap<String, Any?> = stringKeyMap(value)

    private fun stringKeyMap(value: Any?): LinkedHashMap<String, Any?> {
        val source = value as? Map<*, *> ?: return linkedMapOf()
        val result = linkedMapOf<String, Any?>()
        source.forEach { (key, child) ->
            val stringKey = key as? String ?: return@forEach
            result[stringKey] = deepCopyValue(child)
        }
        return result
    }

    private fun deepCopyMap(source: Map<String, Any?>): LinkedHashMap<String, Any?> =
        linkedMapOf<String, Any?>().also { target ->
            source.forEach { (key, value) -> target[key] = deepCopyValue(value) }
        }

    private fun deepCopyValue(value: Any?): Any? = when (value) {
        is Map<*, *> -> stringKeyMap(value)
        is List<*> -> value.map(::deepCopyValue)
        else -> value
    }

    private fun stringList(value: Any?): List<String> =
        (value as? List<*>)?.mapNotNull { it?.toString() } ?: emptyList()

    private fun number(value: Any?): Number? = when (value) {
        is Number -> value
        is String -> value.toDoubleOrNull()
        else -> null
    }

    private companion object {
        const val MAX_CONFIG_BYTES = 2L * 1024L * 1024L
        val APPLICATION_ID =
            Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")
    }
}
