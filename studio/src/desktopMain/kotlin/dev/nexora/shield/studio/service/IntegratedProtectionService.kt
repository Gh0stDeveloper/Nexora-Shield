package dev.nexora.shield.studio.service
import dev.nexora.shield.studio.model.CommandResult
import dev.nexora.shield.studio.model.ShieldProfile
import java.nio.file.Path
import kotlin.io.path.extension
import kotlin.io.path.isRegularFile

data class IntegratedSigning(val keystore:Path,val alias:String,val passwordEnvironment:String,val minSdk:Int)
class IntegratedProtectionService(private val runner:CommandRunner=CommandRunner(timeoutSeconds=45*60)) {
    fun commandFor(artifact:Path,output:Path,report:Path,configuration:Path,profile:ShieldProfile,signing:IntegratedSigning,cliExecutable:String):List<String> {
        require(artifact.isRegularFile() && artifact.extension.lowercase()=="apk") {"Integrated protection requires an existing APK."}
        require(configuration.isRegularFile() && configuration.extension=="nshield-private") {"Select a private engine configuration file."}
        require(signing.keystore.isRegularFile() && signing.alias.isNotBlank()) {"Select a signing keystore and alias."}
        require(signing.minSdk>=24 && signing.passwordEnvironment.matches(Regex("[A-Za-z_][A-Za-z0-9_]*"))) {"Signing requires minSdk >= 24 and a password environment variable name."}
        require(cliExecutable.isNotBlank()) {"CLI executable must not be blank."}
        return listOf(cliExecutable,"protect",artifact.toAbsolutePath().normalize().toString(),"--output",output.toAbsolutePath().normalize().toString(),
            "--public-report",report.toAbsolutePath().normalize().toString(),"--engine-config",configuration.toAbsolutePath().normalize().toString(),
            "--profile",profile.wireValue,"--keystore",signing.keystore.toAbsolutePath().normalize().toString(),"--alias",signing.alias,
            "--ks-pass-env",signing.passwordEnvironment,"--min-sdk",signing.minSdk.toString(),"--force")
    }
    suspend fun protect(artifact:Path,output:Path,report:Path,configuration:Path,profile:ShieldProfile,signing:IntegratedSigning,cliExecutable:String,projectRoot:Path):CommandResult =
        runner.run(commandFor(artifact,output,report,configuration,profile,signing,cliExecutable),projectRoot)
}
