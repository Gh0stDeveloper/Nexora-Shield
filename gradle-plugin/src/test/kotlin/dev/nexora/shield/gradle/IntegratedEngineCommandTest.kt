package dev.nexora.shield.gradle
import java.nio.file.Files
import org.gradle.api.GradleException
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
class IntegratedEngineCommandTest {
 @Test fun privateConfigurationSelectsSharedExecutorAndRefusesLegacyFallback() {
  val config=Files.createTempFile("nexora-engine-",".nshield-private").toFile()
  try {
   val command=mutableListOf("nexora-shield","protect","app.apk");IntegratedEngineCommand.append(command,config)
   assertEquals(listOf("--engine-config",config.absolutePath),command.takeLast(2))
   assertThrows(GradleException::class.java) {IntegratedEngineCommand.append(command,config)}
   for (action in listOf("package-apk","inspect")) {assertThrows(GradleException::class.java) {IntegratedEngineCommand.append(mutableListOf("nexora-shield",action,"app.apk"),config)}}
  } finally {config.delete()}
 }
}
