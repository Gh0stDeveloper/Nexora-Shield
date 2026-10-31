package dev.nexora.shield.studio.service
import dev.nexora.shield.studio.model.ShieldProfile
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
@Tag("integrated-apk")
class IntegratedApkExecutionTest {
 @Test fun studioExecutesTheSharedEngineOnARealApk()=runBlocking {
  fun required(name:String):String=requireNotNull(System.getenv(name)) {"$name is required for integratedEngineTest"}
  val fixture=Path.of(required("NEXORA_INTEGRATED_BASELINE_FIXTURE"));val output=Path.of(required("NEXORA_INTEGRATED_EXECUTION"))
  val result=IntegratedProtectionService().protect(fixture.resolve("baseline-unsigned.apk"),output.resolve("runtime.apk"),output.resolve("runtime.json"),
   output.resolve("engine.nshield-private"),ShieldProfile.MAXIMUM,IntegratedSigning(fixture.resolve("ephemeral-test.p12"),"test","NEXORA_RUNTIME_TEST_PASSWORD",28),required("NEXORA_SHIELD_CLI"),output)
  assertEquals(0,result.exitCode,result.output);val report=SecurityReportLoader().load(output.resolve("runtime.json"))
  assertEquals("o1-integrated-experimental",report.protectionScope);assertTrue(report.signed && report.aligned && !report.productionProtected)
  assertTrue(Files.size(output.resolve("runtime.apk"))>0);assertTrue(Files.size(output.resolve("retrace.nshield-map"))>0)
 }
}
