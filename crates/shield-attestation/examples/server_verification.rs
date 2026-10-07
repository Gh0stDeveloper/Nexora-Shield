use nexora_shield_attestation::{
    AttestationProvider, AttestationRequest, ChallengeDeriver, SampleHmacEvidenceAuthenticator,
    SampleRemotePolicyServer, DEFAULT_CHALLENGE_TTL_MS,
};
use nexora_shield_rasp::RiskLevel;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let now_unix_ms = 1_800_000_000_000_u64;
    let mut challenge_deriver = ChallengeDeriver::new([0x41; 32], [0x51; 16]);
    let challenge = challenge_deriver.issue(
        "dev.nexora.example",
        "release-42",
        "feature:billing",
        now_unix_ms,
        DEFAULT_CHALLENGE_TTL_MS,
    )?;

    // The shared-key provider below exists only so this repository can ship a
    // deterministic, dependency-light verification sample. Production Android
    // deployments should use a platform attestation provider and verify its
    // token on the server.
    let client_sample =
        SampleHmacEvidenceAuthenticator::new("sample-provider", [0x61; 32])?;
    let server_sample =
        SampleHmacEvidenceAuthenticator::new("sample-provider", [0x61; 32])?;

    let mut server = SampleRemotePolicyServer::new(server_sample, 4096);
    server.register_challenge(challenge.clone(), now_unix_ms)?;

    let request = AttestationRequest {
        evidence: client_sample.collect(&challenge)?,
        challenge,
        feature: "billing.purchase".to_owned(),
        local_risk: RiskLevel::Observed,
    };

    let response = server.verify_request(&request, now_unix_ms + 1)?;
    println!(
        "session={:?} build={} verdict={:?}",
        response.session_id, response.build_id, response.verification.verdict
    );
    Ok(())
}
