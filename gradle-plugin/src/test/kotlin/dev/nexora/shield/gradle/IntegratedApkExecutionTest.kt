package dev.nexora.shield.gradle
import java.io.File
import org.gradle.testfixtures.ProjectBuilder
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
/** Requires real CLI/fixture inputs; ordinary unit tasks exclude this tag. */
@Tag("integrated-apk")
class IntegratedApkExecutionTest {
 @Test fun pluginExecutesTheSharedEngineOnARealApk() {
  fun required(name:String):String=requireNotNull(System.getenv(name)) {"$name is required for integratedEngineTest"}
  val fixture=File(required("NEXORA_INTEGRATED_BASELINE_FIXTURE"));val output=File(required("NEXORA_INTEGRATED_EXECUTION"))
  val project=ProjectBuilder.builder().withProjectDir(output).build()
  val task=project.tasks.register("protectFixture",NexoraShieldApkTransformTask::class.java).get()
  task.profile.set("maximum");task.cliExecutable.set(required("NEXORA_SHIELD_CLI"));task.engineConfig.set(File(output,"engine.nshield-private"))
  task.legacyPhaseAOnly.set(false);task.align.set(true);task.allowUnsigned.set(false);task.minSdk.set(28)
  task.publicReports.set(true);task.privateReports.set(false);task.signingKeystore.set(File(fixture,"ephemeral-test.p12"));task.signingAlias.set("test")
  task.storePasswordRef.set("env:NEXORA_RUNTIME_TEST_PASSWORD")
  task.executeProtection(File(fixture,"baseline-unsigned.apk"),File(output,"runtime.apk"),output,output,mapOf(
   "NEXORA_SHIELD_GRADLE_STORE_PASSWORD" to required("NEXORA_RUNTIME_TEST_PASSWORD"),"NEXORA_SHIELD_GRADLE_KEY_PASSWORD" to required("NEXORA_RUNTIME_TEST_PASSWORD")))
  assertTrue(File(output,"runtime.apk").length()>0);assertTrue(File(output,"baseline-unsigned.json").readText().contains("o1-integrated-experimental"));assertTrue(File(output,"retrace.nshield-map").length()>0)
 }
}
