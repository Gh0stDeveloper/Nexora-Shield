use nexora_shield_attestation::{
    AttestationChallenge, AttestationError, AttestationProvider, AttestationRequest,
    AttestationVerdict, BuildRevocation, ChallengeDeriver, EvidenceAvailability,
    FeatureAccessDecision, FeatureDecisionReason, FeatureEvaluationContext, FeaturePolicy,
    OfflineAction, OfflinePolicy, PrivacyAudit, RemotePolicyPayload, ReplayGuard,
    SampleHmacEvidenceAuthenticator, SampleHmacPolicyAuthenticator, SampleRemotePolicyServer,
    SignedPolicyEnvelope, DEFAULT_CHALLENGE_TTL_MS, REMOTE_POLICY_SCHEMA,
};
use nexora_shield_rasp::RiskLevel;
use std::collections::BTreeMap;

const NOW: u64 = 1_800_000_000_000;

fn challenge(
    tag: u8,
    build_id: &str,
    purpose: &str,
) -> Result<AttestationChallenge, AttestationError> {
    let mut deriver = ChallengeDeriver::new([tag; 32], [tag.wrapping_add(1); 16]);
    deriver.issue(
        "dev.nexora.sample",
        build_id,
        purpose,
        NOW,
        DEFAULT_CHALLENGE_TTL_MS,
    )
}

fn base_policy() -> RemotePolicyPayload {
    RemotePolicyPayload {
        schema_version: REMOTE_POLICY_SCHEMA,
        policy_id: "release-policy-42".to_owned(),
        sequence: 42,
        application_id: "dev.nexora.sample".to_owned(),
        issued_unix_ms: NOW - 60_000,
        expires_unix_ms: NOW + 60_000,
        offline: OfflinePolicy {
            max_staleness_ms: 86_400_000,
            default_action: OfflineAction::Degrade,
        },
        revoked_builds: BTreeMap::new(),
        features: BTreeMap::from([
            (
                "billing.purchase".to_owned(),
                FeaturePolicy {
                    max_local_risk: RiskLevel::Observed,
                    require_verified_attestation: true,
                    offline_action: Some(OfflineAction::Deny),
                },
            ),
            (
                "library.playback".to_owned(),
                FeaturePolicy {
                    max_local_risk: RiskLevel::High,
                    require_verified_attestation: false,
                    offline_action: Some(OfflineAction::Allow),
                },
            ),
            (
                "account.profile".to_owned(),
                FeaturePolicy {
                    max_local_risk: RiskLevel::Elevated,
                    require_verified_attestation: true,
                    offline_action: Some(OfflineAction::Degrade),
                },
            ),
        ]),
    }
}

fn signed_policy(
    payload: RemotePolicyPayload,
) -> Result<(SignedPolicyEnvelope, SampleHmacPolicyAuthenticator), AttestationError> {
    let auth = SampleHmacPolicyAuthenticator::new("sample-policy-key", [0x91; 32])?;
    let envelope = SignedPolicyEnvelope::sign(payload, &auth)?;
    Ok((envelope, auth))
}

#[test]
fn i1_attestation_abstraction_binds_evidence_and_redacts_token(
) -> Result<(), Box<dyn std::error::Error>> {
    let challenge = challenge(0x11, "build-i1", "feature:billing")?;
    let provider = SampleHmacEvidenceAuthenticator::new("sample-provider", [0x22; 32])?;

    assert_eq!(provider.availability(), EvidenceAvailability::Available);
    let mut evidence = provider.collect(&challenge)?;
    evidence.validate_binding(&challenge)?;

    let debug = format!("{evidence:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&format!("{:?}", evidence.token)));

    evidence.build_id = "other-build".to_owned();
    assert_eq!(
        evidence.validate_binding(&challenge),
        Err(AttestationError::EvidenceBindingMismatch)
    );
    Ok(())
}

#[test]
fn i2_nonce_and_session_model_are_unique_and_ttl_bounded() -> Result<(), Box<dyn std::error::Error>>
{
    let mut deriver = ChallengeDeriver::new([0x33; 32], [0x34; 16]);
    let first = deriver.issue(
        "dev.nexora.sample",
        "build-i2",
        "login",
        NOW,
        DEFAULT_CHALLENGE_TTL_MS,
    )?;
    let second = deriver.issue(
        "dev.nexora.sample",
        "build-i2",
        "login",
        NOW,
        DEFAULT_CHALLENGE_TTL_MS,
    )?;

    assert_ne!(first.session_id, second.session_id);
    assert_ne!(first.nonce, second.nonce);
    first.validate_at(NOW)?;
    assert_eq!(
        first.validate_at(first.expires_unix_ms + 1),
        Err(AttestationError::ChallengeExpired)
    );

    assert!(deriver
        .issue(
            "dev.nexora.sample",
            "build-i2",
            "login",
            NOW,
            nexora_shield_attestation::MAX_CHALLENGE_TTL_MS + 1,
        )
        .is_err());
    Ok(())
}

#[test]
fn i3_replay_guard_consumes_each_challenge_once() -> Result<(), Box<dyn std::error::Error>> {
    let challenge = challenge(0x44, "build-i3", "license")?;
    let mut guard = ReplayGuard::new(8);

    guard.register(challenge.clone(), NOW)?;
    guard.consume(&challenge, NOW + 1)?;

    assert_eq!(
        guard.consume(&challenge, NOW + 2),
        Err(AttestationError::ReplayDetected)
    );
    Ok(())
}

#[test]
fn i4_server_sample_verifies_and_consumes_rejected_attempts(
) -> Result<(), Box<dyn std::error::Error>> {
    let valid_challenge = challenge(0x55, "build-i4", "feature:profile")?;
    let client = SampleHmacEvidenceAuthenticator::new("sample-provider", [0x66; 32])?;
    let server_verifier = SampleHmacEvidenceAuthenticator::new("sample-provider", [0x66; 32])?;
    let mut server = SampleRemotePolicyServer::new(server_verifier, 16);

    server.register_challenge(valid_challenge.clone(), NOW)?;
    let evidence = client.collect(&valid_challenge)?;
    let request = AttestationRequest {
        challenge: valid_challenge.clone(),
        evidence,
        feature: "account.profile".to_owned(),
        local_risk: RiskLevel::Clean,
    };

    let response = server.verify_request(&request, NOW + 1)?;
    assert_eq!(response.verification.verdict, AttestationVerdict::Verified);

    assert_eq!(
        server.verify_request(&request, NOW + 2),
        Err(AttestationError::ReplayDetected)
    );

    let rejected_challenge = challenge(0x57, "build-i4b", "feature:profile")?;
    let bad_client = SampleHmacEvidenceAuthenticator::new("sample-provider", [0x77; 32])?;
    server.register_challenge(rejected_challenge.clone(), NOW)?;
    let bad_request = AttestationRequest {
        evidence: bad_client.collect(&rejected_challenge)?,
        challenge: rejected_challenge.clone(),
        feature: "account.profile".to_owned(),
        local_risk: RiskLevel::Clean,
    };

    assert!(server.verify_request(&bad_request, NOW + 1).is_err());
    assert_eq!(
        server.verify_request(&bad_request, NOW + 2),
        Err(AttestationError::ReplayDetected)
    );
    Ok(())
}

#[test]
fn i5_signed_policy_rejects_tamper_and_sequence_rollback() -> Result<(), Box<dyn std::error::Error>>
{
    let (envelope, verifier) = signed_policy(base_policy())?;
    let accepted_policy = envelope.verify(&verifier, "dev.nexora.sample", 40, NOW)?;
    assert_eq!(accepted_policy.payload().sequence, 42);

    assert!(matches!(
        envelope.verify(&verifier, "dev.nexora.sample", 43, NOW),
        Err(AttestationError::PolicySequenceRollback {
            minimum: 43,
            observed: 42
        })
    ));

    let mut tampered = envelope.clone();
    tampered.payload.sequence = 99;
    assert_eq!(
        tampered.verify(&verifier, "dev.nexora.sample", 1, NOW),
        Err(AttestationError::InvalidPolicySignature)
    );
    Ok(())
}

#[test]
fn i6_build_revocation_is_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = base_policy();
    payload.revoked_builds.insert(
        "revoked-build".to_owned(),
        BuildRevocation {
            reason_code: "security_regression".to_owned(),
            revoked_unix_ms: NOW - 10_000,
        },
    );
    let (envelope, verifier) = signed_policy(payload)?;
    let policy = envelope.verify(&verifier, "dev.nexora.sample", 1, NOW)?;

    let evaluation = policy.evaluate(&FeatureEvaluationContext {
        build_id: "revoked-build".to_owned(),
        feature: "library.playback".to_owned(),
        local_risk: RiskLevel::Clean,
        attestation: AttestationVerdict::Verified,
        online: true,
        now_unix_ms: NOW,
    })?;

    assert_eq!(evaluation.decision, FeatureAccessDecision::Deny);
    assert_eq!(evaluation.reason, FeatureDecisionReason::BuildRevoked);
    Ok(())
}

#[test]
fn i7_feature_specific_thresholds_do_not_share_one_global_cutoff(
) -> Result<(), Box<dyn std::error::Error>> {
    let (envelope, verifier) = signed_policy(base_policy())?;
    let policy = envelope.verify(&verifier, "dev.nexora.sample", 1, NOW)?;

    let billing = policy.evaluate(&FeatureEvaluationContext {
        build_id: "build-i7".to_owned(),
        feature: "billing.purchase".to_owned(),
        local_risk: RiskLevel::Elevated,
        attestation: AttestationVerdict::Verified,
        online: true,
        now_unix_ms: NOW,
    })?;
    assert_eq!(billing.decision, FeatureAccessDecision::Deny);
    assert_eq!(
        billing.reason,
        FeatureDecisionReason::LocalRiskAboveThreshold
    );

    let playback = policy.evaluate(&FeatureEvaluationContext {
        build_id: "build-i7".to_owned(),
        feature: "library.playback".to_owned(),
        local_risk: RiskLevel::Elevated,
        attestation: AttestationVerdict::Unavailable,
        online: false,
        now_unix_ms: NOW,
    })?;
    assert_eq!(playback.decision, FeatureAccessDecision::Allow);
    Ok(())
}

#[test]
fn i8_offline_degradation_respects_feature_action_and_staleness(
) -> Result<(), Box<dyn std::error::Error>> {
    let mut payload = base_policy();
    payload.expires_unix_ms = NOW - 1_000;
    let (envelope, verifier) = signed_policy(payload)?;
    let policy = envelope.verify(&verifier, "dev.nexora.sample", 1, NOW)?;

    let profile = policy.evaluate(&FeatureEvaluationContext {
        build_id: "build-i8".to_owned(),
        feature: "account.profile".to_owned(),
        local_risk: RiskLevel::Clean,
        attestation: AttestationVerdict::Unavailable,
        online: false,
        now_unix_ms: NOW,
    })?;
    assert_eq!(profile.decision, FeatureAccessDecision::Degraded);
    assert_eq!(profile.reason, FeatureDecisionReason::OfflineCachedPolicy);

    let online = policy.evaluate(&FeatureEvaluationContext {
        online: true,
        ..FeatureEvaluationContext {
            build_id: "build-i8".to_owned(),
            feature: "account.profile".to_owned(),
            local_risk: RiskLevel::Clean,
            attestation: AttestationVerdict::Unavailable,
            online: false,
            now_unix_ms: NOW,
        }
    })?;
    assert_eq!(
        online.decision,
        FeatureAccessDecision::RequireOnlineVerification
    );

    let stale = policy.evaluate(&FeatureEvaluationContext {
        build_id: "build-i8".to_owned(),
        feature: "library.playback".to_owned(),
        local_risk: RiskLevel::Clean,
        attestation: AttestationVerdict::Unavailable,
        online: false,
        now_unix_ms: NOW + 86_400_001,
    })?;
    assert_eq!(stale.decision, FeatureAccessDecision::Deny);
    assert_eq!(stale.reason, FeatureDecisionReason::PolicyTooStale);
    Ok(())
}

#[test]
fn i9_privacy_audit_exposes_no_stable_device_identifier_fields(
) -> Result<(), Box<dyn std::error::Error>> {
    let challenge = challenge(0x99, "build-i9", "feature:profile")?;
    let provider = SampleHmacEvidenceAuthenticator::new("sample-provider", [0xaa; 32])?;
    let request = AttestationRequest {
        evidence: provider.collect(&challenge)?,
        challenge,
        feature: "account.profile".to_owned(),
        local_risk: RiskLevel::Observed,
    };

    let report = PrivacyAudit::inspect_request(&request);
    assert!(report.uses_minimal_request_shape());
    assert_eq!(report.stable_device_identifier_fields, 0);
    assert_eq!(report.free_form_device_metadata_fields, 0);

    let debug = format!("{request:?}");
    assert!(debug.contains("[REDACTED]"));
    Ok(())
}

#[test]
fn i10_end_to_end_attestation_policy_and_offline_flow() -> Result<(), Box<dyn std::error::Error>> {
    let mut deriver = ChallengeDeriver::new([0xbb; 32], [0xbc; 16]);
    let challenge = deriver.issue(
        "dev.nexora.sample",
        "build-i10",
        "feature:profile",
        NOW,
        DEFAULT_CHALLENGE_TTL_MS,
    )?;

    let client = SampleHmacEvidenceAuthenticator::new("sample-provider", [0xcc; 32])?;
    let server_verifier = SampleHmacEvidenceAuthenticator::new("sample-provider", [0xcc; 32])?;
    let mut server = SampleRemotePolicyServer::new(server_verifier, 32);
    server.register_challenge(challenge.clone(), NOW)?;

    let request = AttestationRequest {
        evidence: client.collect(&challenge)?,
        challenge,
        feature: "account.profile".to_owned(),
        local_risk: RiskLevel::Observed,
    };
    let server_response = server.verify_request(&request, NOW + 10)?;
    assert_eq!(
        server_response.verification.verdict,
        AttestationVerdict::Verified
    );

    let (envelope, verifier) = signed_policy(base_policy())?;
    let policy = envelope.verify(&verifier, "dev.nexora.sample", 42, NOW)?;
    let online = policy.evaluate(&FeatureEvaluationContext {
        build_id: server_response.build_id,
        feature: server_response.feature,
        local_risk: server_response.local_risk,
        attestation: server_response.verification.verdict,
        online: true,
        now_unix_ms: NOW,
    })?;
    assert_eq!(online.decision, FeatureAccessDecision::Allow);

    let offline = policy.evaluate(&FeatureEvaluationContext {
        build_id: "build-i10".to_owned(),
        feature: "account.profile".to_owned(),
        local_risk: RiskLevel::Observed,
        attestation: AttestationVerdict::Unavailable,
        online: false,
        now_unix_ms: NOW,
    })?;
    assert_eq!(offline.decision, FeatureAccessDecision::Degraded);
    assert_eq!(offline.reason, FeatureDecisionReason::OfflineFallback);
    Ok(())
}
