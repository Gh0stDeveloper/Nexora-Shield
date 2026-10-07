use crate::api::STABLE_CONFIG_SCHEMA;
use crate::error::{ReleaseError, Result};
use serde_json::{Map, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct MigrationOutcome {
    pub source_schema: u32,
    pub target_schema: u32,
    pub changed: bool,
    pub document: Value,
}

pub fn migrate_to_current(mut document: Value) -> Result<MigrationOutcome> {
    let root = document.as_object_mut().ok_or_else(|| {
        ReleaseError::InvalidMigration("configuration root must be an object".into())
    })?;

    let declared = root
        .get("schema")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok());

    match declared {
        Some(STABLE_CONFIG_SCHEMA) => {
            validate_current(root)?;
            Ok(MigrationOutcome {
                source_schema: STABLE_CONFIG_SCHEMA,
                target_schema: STABLE_CONFIG_SCHEMA,
                changed: false,
                document,
            })
        }
        Some(version) if version > STABLE_CONFIG_SCHEMA => Err(ReleaseError::InvalidMigration(
            format!("schema {version} is newer than supported schema {STABLE_CONFIG_SCHEMA}"),
        )),
        Some(0) | None => migrate_legacy(document, declared.unwrap_or(0)),
        Some(version) => Err(ReleaseError::InvalidMigration(format!(
            "no migration path exists from schema {version}"
        ))),
    }
}

fn migrate_legacy(mut document: Value, source_schema: u32) -> Result<MigrationOutcome> {
    let root = document.as_object_mut().ok_or_else(|| {
        ReleaseError::InvalidMigration("configuration root must be an object".into())
    })?;

    if root.contains_key("application") {
        root.insert("schema".into(), Value::from(STABLE_CONFIG_SCHEMA));
        validate_current(root)?;
        return Ok(MigrationOutcome {
            source_schema,
            target_schema: STABLE_CONFIG_SCHEMA,
            changed: true,
            document,
        });
    }

    let application_id = root
        .remove("applicationId")
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .ok_or_else(|| {
            ReleaseError::InvalidMigration(
                "legacy configuration requires string applicationId".into(),
            )
        })?;
    let min_sdk = root
        .remove("minSdk")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| {
            ReleaseError::InvalidMigration("legacy configuration requires integer minSdk".into())
        })?;
    let profile = root
        .remove("protectionProfile")
        .or_else(|| root.remove("profile"))
        .unwrap_or_else(|| Value::from("hardened"));

    let mut application = Map::new();
    application.insert("id".into(), Value::from(application_id));
    application.insert("minSdk".into(), Value::from(min_sdk));

    root.insert("schema".into(), Value::from(STABLE_CONFIG_SCHEMA));
    root.insert("application".into(), Value::Object(application));
    root.insert("profile".into(), profile);
    validate_current(root)?;

    Ok(MigrationOutcome {
        source_schema,
        target_schema: STABLE_CONFIG_SCHEMA,
        changed: true,
        document,
    })
}

fn validate_current(root: &Map<String, Value>) -> Result<()> {
    let application = root
        .get("application")
        .and_then(Value::as_object)
        .ok_or_else(|| ReleaseError::InvalidMigration("application section is required".into()))?;
    let id = application
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| ReleaseError::InvalidMigration("application.id is required".into()))?;
    if !valid_application_id(id) {
        return Err(ReleaseError::InvalidMigration(
            "application.id is not a valid dotted Android application id".into(),
        ));
    }
    let min_sdk = application
        .get("minSdk")
        .and_then(Value::as_u64)
        .ok_or_else(|| ReleaseError::InvalidMigration("application.minSdk is required".into()))?;
    if min_sdk < u64::from(crate::api::MINIMUM_ANDROID_SDK) {
        return Err(ReleaseError::InvalidMigration(format!(
            "application.minSdk must be at least {}",
            crate::api::MINIMUM_ANDROID_SDK
        )));
    }

    let profile = root
        .get("profile")
        .and_then(Value::as_str)
        .ok_or_else(|| ReleaseError::InvalidMigration("profile is required".into()))?;
    if !matches!(profile, "standard" | "hardened" | "maximum") {
        return Err(ReleaseError::InvalidMigration(format!(
            "unsupported protection profile '{profile}'"
        )));
    }
    Ok(())
}

fn valid_application_id(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() >= 2
        && parts.iter().all(|part| {
            let mut chars = part.chars();
            chars
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic())
                && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
        })
}
