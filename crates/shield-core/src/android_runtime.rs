//! Functional Android runtime staging for explicitly eligible static methods.
//! The complete protection graph remains fail-closed; this is not a production release.

pub use crate::runtime_smali::SmaliTools;
#[path = "runtime_constants.rs"]
mod constants;
#[path = "android_guard.rs"]
mod guard;
use crate::{
    input_snapshot::InputSnapshot,
    runtime_smali::{self, refuse, HELPER},
    ProductionBuildContext, Result, MAX_DEX_BYTES, MAX_TOTAL_DEX_BYTES,
};
use nexora_shield_crypto::BuildIdentity;
use nexora_shield_dex::{
    canonical_dex_index, canonical_dex_name, DexInput, MultiDexSet, ReferenceKind,
};
use nexora_shield_native::{RuntimeEntryKind, RuntimeImage};
use nexora_shield_package::{
    is_legacy_signature_entry, read_decoded_entry, read_zip_directory, rewrite_with_additions,
    sha256_file, verify_apk_structure, verify_preserved_entry_payload,
};
use nexora_shield_vm::{DexLowerer, EligibilityPolicy};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
};

struct MethodBinding {
    dex: usize,
    owner: String,
    signature: String,
    slot: u32,
    arguments: usize,
    kind: RuntimeEntryKind,
}

pub struct AndroidRuntimePlan {
    context: ProductionBuildContext,
    snapshot: InputSnapshot,
    units: Vec<DexInput>,
    bindings: Vec<MethodBinding>,
    image: RuntimeImage,
    guard: Option<guard::GuardBuild>,
}
impl fmt::Debug for AndroidRuntimePlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AndroidRuntimePlan")
            .field("methods", &self.bindings.len())
            .field("image", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeStageEvidence {
    pub input_sha256: String,
    pub output_sha256: String,
    pub runtime_fingerprint: String,
    pub protected_strings: usize,
    pub protected_constants: usize,
    pub virtualized_methods: usize,
    pub dex_units: usize,
    pub native_sha256: BTreeMap<String, String>,
}

impl ProductionBuildContext {
    /// Plan real call-site replacements and build-bound runtime ciphertext.
    /// # Errors
    /// Requires explicit method-only selectors; every selected method must be eligible.
    pub fn prepare_android_runtime(
        &self,
        root: &[u8; 32],
        mut identity: BuildIdentity,
    ) -> Result<AndroidRuntimePlan> {
        if self.selectors().includes().is_empty() {
            return Err(refuse("Android runtime requires explicit method selection"));
        }
        self.verify_input_unchanged()?;
        let snapshot = InputSnapshot::capture(self.input(), self.input_sha256())?;
        let path = snapshot.path();
        let directory = read_zip_directory(&path)?;
        let manifest = directory
            .entries
            .iter()
            .find(|entry| entry.name == "AndroidManifest.xml")
            .ok_or_else(|| refuse("missing Android manifest"))?;
        let bytes = read_decoded_entry(&path, manifest, 16 * 1024 * 1024)?;
        let (application_id, _) = crate::android_binary_xml::runtime_manifest_contract(&bytes)?;
        if application_id != identity.application_id {
            return Err(refuse(
                "runtime identity differs from the compiled Android package",
            ));
        }
        let mut units = Vec::new();
        let mut total = 0usize;
        for entry in &directory.entries {
            if canonical_dex_index(&entry.name).is_none() {
                continue;
            }
            let bytes = read_decoded_entry(&path, entry, MAX_DEX_BYTES)?;
            total = total
                .checked_add(bytes.len())
                .ok_or_else(|| refuse("DEX budget overflow"))?;
            if total > MAX_TOTAL_DEX_BYTES {
                return Err(refuse("DEX memory budget exceeded"));
            }
            units.push(DexInput {
                name: entry.name.clone(),
                bytes,
            });
        }
        let set =
            MultiDexSet::parse(units.clone()).map_err(|_| refuse("invalid runtime DEX input"))?;
        // Freeze canonical ordering, independent of ZIP central-directory order.
        units = set
            .units
            .iter()
            .map(|u| DexInput {
                name: u.name.clone(),
                bytes: u.dex.bytes.clone(),
            })
            .collect();
        let selection = crate::dex_preflight::resolve_effective_selection(&set, self.selectors())?;
        identity.build_id = format!("{}:{}", identity.build_id, self.input_sha256());
        let mut image = RuntimeImage::new(root, identity)
            .map_err(|_| refuse("invalid runtime build identity"))?;
        let mut bindings = Vec::new();
        for (dex_index, (unit, selected)) in set.units.iter().zip(selection).enumerate() {
            if !selected.classes.is_empty() || !selected.fields.is_empty() {
                return Err(refuse("runtime selection must contain methods only"));
            }
            if unit
                .dex
                .types
                .iter()
                .any(|t| unit.dex.string(t.descriptor_idx) == Some(HELPER))
            {
                return Err(refuse("runtime helper namespace already referenced"));
            }
            for index in selected.methods {
                let slot = u32::try_from(bindings.len())
                    .map_err(|_| refuse("too many runtime methods"))?;
                if slot >= 256 {
                    return Err(refuse("runtime method selection exceeds 256 methods"));
                }
                let (owner, signature, arguments) = binding_identity(&unit.dex, index)?;
                let kind = protect_binding(&unit.dex, index, slot, &mut image)?;
                bindings.push(MethodBinding {
                    dex: dex_index,
                    owner,
                    signature,
                    slot,
                    arguments,
                    kind,
                });
            }
        }
        image
            .validate()
            .map_err(|_| refuse("empty or invalid runtime image"))?;
        self.verify_input_unchanged()?;
        Ok(AndroidRuntimePlan {
            context: self.clone(),
            snapshot,
            units,
            bindings,
            image,
            guard: None,
        })
    }
}

impl AndroidRuntimePlan {
    /// Build-private configuration contains client key shares; never publish it.
    /// # Errors
    /// Requires a new Unix 0600 file with the ignored `.nshield-private` suffix.
    pub fn write_native_configuration(&self, path: &Path) -> Result<()> {
        if path.extension().and_then(|s| s.to_str()) != Some("nshield-private") {
            return Err(refuse(
                "private runtime config requires .nshield-private suffix",
            ));
        }
        if crate::production::normalized_destination(path)?
            == crate::production::normalized_destination(self.context.output())?
        {
            return Err(refuse("runtime configuration collides with APK output"));
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            return Err(refuse(
                "private runtime build configuration requires Unix permissions",
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let encoded = zeroize::Zeroizing::new(
                serde_json::to_vec(&self.image)
                    .map_err(|_| refuse("runtime image encoding failed"))?,
            );
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?;
            if let Err(error) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
                drop(file);
                let _ = fs::remove_file(path);
                return Err(error.into());
            }
            Ok(())
        }
    }

    /// Build and verify an unsigned APK that actually calls the data/VM JNI runtime.
    /// # Errors
    /// Rejects incompatible libraries, unsafe selection, tool failures and any unplanned change.
    pub fn stage(
        self,
        destination: &Path,
        tools: &SmaliTools,
        native_directory: &Path,
    ) -> Result<RuntimeStageEvidence> {
        let normalized = crate::production::normalized_destination(destination)?;
        if fs::symlink_metadata(destination).is_ok()
            || normalized == self.context.input()
            || normalized == self.context.output()
        {
            return Err(refuse(
                "runtime staging output must be new and separate from planned production output",
            ));
        }
        self.context.verify_input_unchanged()?;
        let source = self.snapshot.path();
        let directory = read_zip_directory(&source)?;
        let fingerprint = self
            .image
            .fingerprint()
            .map_err(|_| refuse("invalid runtime fingerprint"))?;
        let (mut additions, native_hashes) = native_inputs(native_directory, &fingerprint)?;
        for entry in &directory.entries {
            if entry.name.starts_with("lib/") {
                let abi = entry.name.split('/').nth(1).unwrap_or("");
                if !["arm64-v8a", "x86_64"].contains(&abi) {
                    return Err(refuse("APK contains an ABI without a matching runtime"));
                }
            }
        }
        let root = source
            .parent()
            .ok_or_else(|| refuse("invalid runtime workspace"))?;
        let mut replacements = self.rewrite_units(tools, root)?;
        let helper = root.join("runtime-helper");
        fs::create_dir_all(helper.join("dev/nexora/shield"))?;
        fs::write(
            helper.join("dev/nexora/shield/NativeShield.smali"),
            runtime_smali::ordered_methods(&runtime_smali::helper(&fingerprint)),
        )?;
        if self.guard.is_some() {
            fs::write(
                helper.join("dev/nexora/shield/NexoraProvider.smali"),
                runtime_smali::ordered_methods(&runtime_smali::provider()),
            )?;
        }
        let helper_bytes = assemble_verified(
            tools,
            &helper,
            &root.join("helper.dex"),
            &root.join("verify-helper"),
        )?;
        additions.insert(
            canonical_dex_name(
                u32::try_from(self.units.len() + 1).map_err(|_| refuse("too many DEX units"))?,
            ),
            helper_bytes,
        );
        self.add_guard(&mut replacements, &mut additions)?;
        self.context.verify_input_unchanged()?;
        rewrite_with_additions(&source, destination, &replacements, &additions)?;
        let verified = (|| {
            verify_runtime_output(&source, destination, &replacements, &additions)?;
            self.context.verify_input_unchanged()?;
            Ok(RuntimeStageEvidence {
                input_sha256: self.context.input_sha256().to_owned(),
                output_sha256: sha256_file(destination)?,
                runtime_fingerprint: fingerprint,
                protected_strings: self
                    .bindings
                    .iter()
                    .filter(|b| b.kind == RuntimeEntryKind::String)
                    .count(),
                protected_constants: self
                    .bindings
                    .iter()
                    .filter(|binding| binding.kind == RuntimeEntryKind::Constant)
                    .count(),
                virtualized_methods: self
                    .bindings
                    .iter()
                    .filter(|b| b.kind == RuntimeEntryKind::IntVm)
                    .count(),
                dex_units: self.units.len() + 1,
                native_sha256: native_hashes,
            })
        })();
        if verified.is_err() {
            let _ = fs::remove_file(destination);
        }
        verified
    }
}

impl AndroidRuntimePlan {
    fn rewrite_units(&self, tools: &SmaliTools, root: &Path) -> Result<RuntimePayloads> {
        let mut replacements = BTreeMap::new();
        for (index, unit) in self.units.iter().enumerate() {
            if !self.bindings.iter().any(|b| b.dex == index) {
                continue;
            }
            let input = root.join(format!("unit-{index}.dex"));
            fs::write(&input, &unit.bytes)?;
            let smali = root.join(format!("smali-{index}"));
            tools.disassemble(&input, &smali)?;
            for binding in self.bindings.iter().filter(|b| b.dex == index) {
                let path = smali.join(format!(
                    "{}.smali",
                    &binding.owner[1..binding.owner.len() - 1]
                ));
                let original =
                    String::from_utf8(runtime_smali::read_bounded(&path, 64 * 1024 * 1024)?)
                        .map_err(|_| refuse("invalid smali text"))?;
                let body = match binding.kind {
                    RuntimeEntryKind::Constant => runtime_smali::constant_stub(
                        binding.slot,
                        binding
                            .signature
                            .chars()
                            .last()
                            .ok_or_else(|| refuse("missing constant signature"))?,
                    )?,
                    RuntimeEntryKind::String => runtime_smali::string_stub(binding.slot),
                    RuntimeEntryKind::IntVm => {
                        runtime_smali::int_stub(binding.slot, binding.arguments)
                    }
                };
                fs::write(
                    path,
                    runtime_smali::replace_method(&original, &binding.signature, &body)?,
                )?;
            }
            let built = assemble_verified(
                tools,
                &smali,
                &root.join(format!("built-{index}.dex")),
                &root.join(format!("verify-{index}")),
            )?;
            replacements.insert(unit.name.clone(), built);
        }
        Ok(replacements)
    }
}

fn assemble_verified(
    tools: &SmaliTools,
    source: &Path,
    built: &Path,
    verification: &Path,
) -> Result<Vec<u8>> {
    let expected = runtime_smali::source_inventory(source)?;
    tools.assemble(source, built)?;
    tools.disassemble(built, verification)?;
    if runtime_smali::source_inventory(verification)? != expected {
        return Err(refuse(
            "smali round-trip altered declarations or instructions outside the plan",
        ));
    }
    runtime_smali::read_bounded(built, MAX_DEX_BYTES)
}

fn verify_runtime_output(
    source: &Path,
    output: &Path,
    replacements: &BTreeMap<String, Vec<u8>>,
    additions: &BTreeMap<String, Vec<u8>>,
) -> Result<()> {
    verify_apk_structure(output)?;
    let original = read_zip_directory(source)?;
    let built = read_zip_directory(output)?;
    let mut dex = Vec::new();
    let mut observed = BTreeSet::new();
    for entry in &built.entries {
        if is_legacy_signature_entry(&entry.name) {
            return Err(refuse("stale APK signature"));
        }
        if let Some(expected) = replacements
            .get(&entry.name)
            .or_else(|| additions.get(&entry.name))
        {
            let actual = read_decoded_entry(output, entry, 64 * 1024 * 1024)?;
            if &actual != expected {
                return Err(refuse("final runtime payload differs from verified input"));
            }
            observed.insert(entry.name.clone());
        } else {
            let before = original
                .entries
                .iter()
                .find(|e| e.name == entry.name)
                .ok_or_else(|| refuse("unexpected output entry"))?;
            verify_preserved_entry_payload(source, before, output, entry)?;
        }
        if canonical_dex_index(&entry.name).is_some() {
            dex.push(DexInput {
                name: entry.name.clone(),
                bytes: read_decoded_entry(output, entry, MAX_DEX_BYTES)?,
            });
        }
    }
    let expected_count = original
        .entries
        .iter()
        .filter(|e| !is_legacy_signature_entry(&e.name))
        .count()
        + additions.len();
    if observed.len() != replacements.len() + additions.len()
        || built.entries.len() != expected_count
    {
        return Err(refuse("runtime APK inventory mismatch"));
    }
    MultiDexSet::parse(dex).map_err(|_| refuse("final runtime multidex validation failed"))?;
    Ok(())
}

fn binding_identity(
    dex: &nexora_shield_dex::DexFile,
    index: u32,
) -> Result<(String, String, usize)> {
    let encoded = dex
        .encoded_method(index)
        .ok_or_else(|| refuse("selected runtime method is not defined"))?;
    if encoded.access_flags & 0x8 == 0
        || encoded.access_flags & (0x20 | 0x100 | 0x400 | 0x20000) != 0
    {
        return Err(refuse(
            "runtime method must be static, executable and unsynchronized",
        ));
    }
    let method = &dex.methods[index as usize];
    let proto = &dex.protos[usize::from(method.proto_idx)];
    let owner = dex
        .type_descriptor(u32::from(method.class_idx))
        .ok_or_else(|| refuse("invalid runtime owner"))?
        .to_owned();
    if !owner[1..owner.len() - 1]
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/_$".contains(&b))
    {
        return Err(refuse("unsupported runtime class path"));
    }
    let name = dex
        .method_name(index)
        .ok_or_else(|| refuse("invalid runtime method name"))?;
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_$".contains(&b))
    {
        return Err(refuse("unsupported runtime method name"));
    }
    let mut signature = format!("{name}(");
    for parameter in &proto.parameters {
        signature.push_str(
            dex.type_descriptor(u32::from(*parameter))
                .ok_or_else(|| refuse("invalid parameter"))?,
        );
    }
    signature.push(')');
    let return_type = dex
        .type_descriptor(proto.return_type_idx)
        .ok_or_else(|| refuse("invalid return type"))?;
    signature.push_str(return_type);
    Ok((owner, signature, proto.parameters.len()))
}
fn protect_binding(
    dex: &nexora_shield_dex::DexFile,
    index: u32,
    slot: u32,
    image: &mut RuntimeImage,
) -> Result<RuntimeEntryKind> {
    if let Some(kind) = constants::protect_literal(dex, index, slot, image)? {
        return Ok(kind);
    }
    let method = &dex.methods[index as usize];
    let proto = &dex.protos[usize::from(method.proto_idx)];
    let return_type = dex
        .type_descriptor(proto.return_type_idx)
        .ok_or_else(|| refuse("invalid return type"))?;
    let kind = if return_type == "Ljava/lang/String;" && proto.parameters.is_empty() {
        let code = dex
            .code_for_method(index)
            .ok_or_else(|| refuse("missing string method code"))?;
        let instructions = &code.instructions;
        if !code.tries.is_empty()
            || instructions.len() != 2
            || !matches!(instructions[0].opcode, 0x1a | 0x1b)
            || instructions[1].opcode != 0x11
            || code.insns[0] >> 8 != code.insns[instructions[1].offset as usize] >> 8
        {
            return Err(refuse(
                "string runtime currently requires a literal-only return method",
            ));
        }
        let Some((ReferenceKind::String, string)) = instructions[0].reference else {
            return Err(refuse("invalid string reference"));
        };
        image
            .protect_string(
                slot,
                dex.string(string)
                    .ok_or_else(|| refuse("invalid string value"))?,
            )
            .map_err(|_| refuse("runtime string protection failed"))?;
        RuntimeEntryKind::String
    } else if return_type == "I"
        && proto.parameters.len() <= 16
        && proto
            .parameters
            .iter()
            .all(|t| dex.type_descriptor(u32::from(*t)) == Some("I"))
    {
        let lowered = DexLowerer::lower(
            dex,
            index,
            EligibilityPolicy {
                allow_calls: false,
                allow_fields: false,
                allow_exceptions: false,
                ..EligibilityPolicy::default()
            },
        )
        .map_err(|_| refuse("selected integer method is not VM eligible"))?;
        image.protect_int_vm(slot, &lowered).map_err(|_| {
            refuse("selected VM method exceeds the supported pure integer contract")
        })?;
        RuntimeEntryKind::IntVm
    } else {
        return Err(refuse(
            "selected method signature is not supported by the Android runtime",
        ));
    };
    Ok(kind)
}

type RuntimePayloads = BTreeMap<String, Vec<u8>>;
fn native_inputs(
    native_directory: &Path,
    fingerprint: &str,
) -> Result<(RuntimePayloads, BTreeMap<String, String>)> {
    let marker = format!("NEXORA_RUNTIME_V1:{fingerprint}");
    let mut additions = BTreeMap::new();
    let mut native_hashes = BTreeMap::new();
    for abi in ["arm64-v8a", "x86_64"] {
        let name = format!("lib/{abi}/libnexora_shield_native.so");
        let path = native_directory
            .join(abi)
            .join("libnexora_shield_native.so");
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() || metadata.len() > 64 * 1024 * 1024 {
            return Err(refuse("invalid native runtime input"));
        }
        let bytes = runtime_smali::read_bounded(&path, 64 * 1024 * 1024)?;
        let exports = crate::android_jni::inspect_native_elf(&bytes, &name)?;
        let required = nexora_shield_native::REQUIRED_JNI_EXPORTS
            .iter()
            .chain(nexora_shield_native::RUNTIME_JNI_EXPORTS.iter())
            .copied()
            .collect::<BTreeSet<_>>();
        let actual = exports
            .static_jni
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if actual != required || exports.has_jni_onload {
            return Err(refuse("native runtime JNI contract mismatch"));
        }
        if !bytes.windows(marker.len()).any(|w| w == marker.as_bytes())
            || bytes.windows(10).any(|w| w == b"libc.so.6\0")
        {
            return Err(refuse(
                "native runtime build binding or Android target mismatch",
            ));
        }
        native_hashes.insert(
            abi.to_owned(),
            nexora_shield_crypto::hex_lower(&nexora_shield_crypto::sha256(&bytes)),
        );
        additions.insert(name, bytes);
    }
    Ok((additions, native_hashes))
}
