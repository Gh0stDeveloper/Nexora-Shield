package dev.nexora.shield.studio.service
import dev.nexora.shield.studio.model.ShieldProfile
import java.nio.file.Files
import kotlin.test.*
class IntegratedProtectionServiceTest {
 @Test fun studioUsesSharedExecutorAndPassesOnlySecretReferences() {
  val root=Files.createTempDirectory("nexora-studio-engine-")
  try {
   val apk=Files.write(root.resolve("input.apk"),byteArrayOf(1));val config=Files.write(root.resolve("engine.nshield-private"),byteArrayOf(1));val key=Files.write(root.resolve("test.p12"),byteArrayOf(1))
   val signing=IntegratedSigning(key,"test","NEXORA_TEST_PASSWORD",28);val service=IntegratedProtectionService()
   val command=service.commandFor(apk,root.resolve("output.apk"),root.resolve("report.json"),config,ShieldProfile.MAXIMUM,signing,"nexora-shield")
   assertEquals("protect",command[1]);assertEquals(config.toString(),command[command.indexOf("--engine-config")+1]);assertTrue(command.contains("NEXORA_TEST_PASSWORD"))
   assertFalse(command.contains("--plan-only"));assertFalse(command.contains("package-apk"));assertFalse(command.contains("--unsigned"))
   assertFailsWith<IllegalArgumentException> {service.commandFor(apk,root.resolve("output.apk"),root.resolve("report.json"),config,ShieldProfile.MAXIMUM,signing.copy(passwordEnvironment="literal password"),"nexora-shield")}
  } finally {root.toFile().deleteRecursively()}
 }
}
