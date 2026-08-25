// NOTE: Usage of allow(dead_code) is intentional here, as fields are used in the Debug macro,
// but the compiler doesn't seem to be able to infer it directly.

/// Represents a specific protocol version supported by the prover, from prover's perspective.
#[derive(Debug)]
#[allow(dead_code)]
struct ProtocolVersion {
    /// verification key hash identifying this protocol version
    vk_hash: VerificationKeyHash,
    /// version of airbender used
    /// NOTE: this can be inferred from vk_hash, but we keep it here for easier cross-checking
    airbender_version: AirbenderVersion,
    /// version of zksync os used
    /// NOTE: this can be inferred from vk_hash, but we keep it here for easier cross-checking
    zksync_os_version: ZkSyncOSVersion,
    /// version of zkos wrapper used
    /// NOTE: this can be inferred from vk_hash, but we keep it here for easier cross-checking
    zkos_wrapper: ZkOsWrapperVersion,
    /// md5sum of the prover binary used for proving
    /// NOTE: in the future we may want to support multiple binaries (such as debug mode)
    /// NOTE2: this can be inferred from zksync_os_version, but we keep it here for easier cross-checking
    bin_md5sum: BinMd5Sum,
    /// SYSCOIN: Chain commitment of the app program this version proves (see
    /// [`ProgramCommitment`]).
    /// The SNARK wrapper bakes it into the VK (registers 18..=25 == aux_params, via
    /// `check_aux_params`), so `vk_hash` alone identifies the app program again; this field
    /// is the plaintext of that binding, used to reject wrong-program FRI proofs up front
    /// and to re-derive/verify the VK.
    program_commitment: ProgramCommitment,
    /// SYSCOIN: Required FRI proving security level at which this canonical lane's constants were
    /// generated (see [`SecurityLevel`]); it cannot fall back to an implicit upstream default.
    security_level: SecurityLevel,
}

/// FRI proving security level of a protocol version. The level selects the recursion
/// verifier binaries, so `program_commitment` and `vk_hash` are specific to it: the
/// values for the same app binary at another level differ and are not interchangeable,
/// which is why the level is recorded here, next to the constants it invalidates.
///
/// Mirrors airbender's `SecurityLevel` as plain data (this crate has no dependencies);
/// the prover crates map it to airbender's type where they configure proving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    // SYSCOIN: The canonical V32 lane is generated exclusively at 100-bit security.
    /// 100-bit security.
    Security100,
}

/// SYSCOIN: Blake2s recursion-chain commitment binding a protocol version to its app program: the
/// base program's `end_params` folded first with the unrolled verifier and then with the
/// unified verifier — the value wrapper-ready proofs expose in final registers 18..=25.
/// The SNARK wrapper constrains those registers to this value in-circuit
/// (`check_aux_params`), so the app program is bound through the VK rather than carried in
/// the SNARK public input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramCommitment(pub [u32; 8]);

impl std::fmt::Display for ProgramCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x")?;
        for word in self.0 {
            write!(f, "{word:08x}")?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct VerificationKeyHash(&'static str);
#[derive(Debug)]
#[allow(dead_code)]
struct AirbenderVersion(&'static str);
#[derive(Debug)]
#[allow(dead_code)]
struct ZkSyncOSVersion(&'static str);
#[derive(Debug)]
#[allow(dead_code)]
struct ZkOsWrapperVersion(&'static str);
#[derive(Debug)]
#[allow(dead_code)]
struct BinMd5Sum(&'static str);

// SYSCOIN: The zero VK is a fail-closed release sentinel; bind the sole supported lane to the
// reproducible compact-Bitcoin-DA guest only after V32 key generation replaces it.
const ZERO_VK_HASH: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
const SYSCOIN_APP_MD5: &str = "5117d5dac6dbd34b93fef54e04d0b41c";
const SYSCOIN_PROGRAM_COMMITMENT: ProgramCommitment = ProgramCommitment([
    0x0d2bc42e, 0xeea78bfb, 0x08553eb9, 0xe18ee1ef, 0xa4a97e19, 0x9b5db62d, 0x9972e789, 0x24d28425,
]);

/// SYSCOIN: The sole canonical lane is protocol V32, Execution V7, Proving V8.
/// It uses the patched zksync-os v0.4.0 app with compact Bitcoin DA.
const SYSCOIN_V32_EXECUTION_V7_PROVING_V8: ProtocolVersion = ProtocolVersion {
    // Keccak256 of the phase-3 SNARK VK (`generate-vk --check-aux-params`), so it binds the
    // app binary below. The zero sentinel deliberately blocks deployment until keygen.
    vk_hash: VerificationKeyHash(ZERO_VK_HASH),
    airbender_version: AirbenderVersion("v0.6.0-rc.2"),
    zksync_os_version: ZkSyncOSVersion("v0.4.0"),
    zkos_wrapper: ZkOsWrapperVersion("v0.6.0-rc.2"),
    bin_md5sum: BinMd5Sum(SYSCOIN_APP_MD5),
    // base -> unrolled -> unified: what real proofs expose in registers 18..=25.
    // Specific to the 100-bit level below, like the vk_hash above.
    program_commitment: SYSCOIN_PROGRAM_COMMITMENT,
    security_level: SecurityLevel::Security100,
};

/// Represents the set of supported protocol versions by this prover implementation.
#[derive(Debug)]
pub struct SupportedProtocolVersions {
    versions: Vec<ProtocolVersion>,
}

impl Default for SupportedProtocolVersions {
    fn default() -> Self {
        // SYSCOIN: Fresh-chain releases intentionally expose one canonical protocol lane.
        Self {
            versions: vec![SYSCOIN_V32_EXECUTION_V7_PROVING_V8],
        }
    }
}

impl SupportedProtocolVersions {
    /// SYSCOIN: Fail closed until keygen replaces the zero VK sentinel, and ensure the
    /// remaining release constants are exactly the patched Syscoin app values.
    pub fn ensure_syscoin_release_constants(&self) -> Result<(), String> {
        let [version] = self.versions.as_slice() else {
            return Err("the prover must contain exactly one canonical Syscoin version".to_owned());
        };
        if version.bin_md5sum.0 != SYSCOIN_APP_MD5
            || version.program_commitment != SYSCOIN_PROGRAM_COMMITMENT
            || version.security_level != SecurityLevel::Security100
        {
            return Err("canonical Syscoin app/security constants do not match".to_owned());
        }
        if version.vk_hash.0 == ZERO_VK_HASH {
            return Err(
                "Syscoin app-bound V8 VK is the zero regeneration sentinel; run production \
                 keygen and update the prover, server, and Era verifier atomically"
                    .to_owned(),
            );
        }
        if version.vk_hash.0.len() != 66
            || !version.vk_hash.0.starts_with("0x")
            || !version.vk_hash.0[2..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("Syscoin app-bound V8 VK hash is not a 32-byte hex value".to_owned());
        }
        Ok(())
    }

    /// Checks if the given VK hash is supported.
    pub fn contains(&self, vk_hash: &str) -> bool {
        self.versions.iter().any(|v| v.vk_hash.0 == vk_hash)
    }

    /// Returns the list of supported VK hashes as strings.
    pub fn vk_hashes(&self) -> Vec<String> {
        self.versions
            .iter()
            .map(|version| version.vk_hash.0.to_string())
            .collect()
    }

    /// SYSCOIN: The app-program commitment recorded for the version with this VK hash;
    /// `None` if the VK hash is unsupported.
    pub fn program_commitment_for(&self, vk_hash: &str) -> Option<ProgramCommitment> {
        self.versions
            .iter()
            .find(|v| v.vk_hash.0 == vk_hash)
            .map(|v| v.program_commitment)
    }

    /// SYSCOIN: Checks the canonical lane's required app commitment without an unbound fallback.
    pub fn supports_program(&self, commitment: &ProgramCommitment) -> bool {
        self.versions
            .iter()
            .any(|v| &v.program_commitment == commitment)
    }

    /// SYSCOIN: Returns the sole canonical lane's required fixed proving security level.
    pub fn proving_security_level(&self) -> SecurityLevel {
        self.versions
            .first()
            .expect("one canonical version")
            .security_level
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Pinning the value guards the V8 constants against a level edit that forgets
    /// to regenerate `program_commitment` and `vk_hash` with it.
    #[test]
    fn default_versions_share_one_proving_security_level() {
        assert_eq!(
            SupportedProtocolVersions::default().proving_security_level(),
            SecurityLevel::Security100
        );
    }

    #[test]
    fn zero_vk_sentinel_blocks_deployment() {
        let error = SupportedProtocolVersions::default()
            .ensure_syscoin_release_constants()
            .expect_err("zero VK sentinel must keep the deployment gate closed");
        assert!(error.contains("zero regeneration sentinel"));
    }

    #[test]
    fn canonical_app_constants_match_checked_in_syscoin_artifacts() {
        let versions = SupportedProtocolVersions::default();
        let [version] = versions.versions.as_slice() else {
            panic!("expected one canonical version")
        };
        assert_eq!(version.bin_md5sum.0, "5117d5dac6dbd34b93fef54e04d0b41c");
        let app_bin = include_bytes!("../../../multiblock_batch.bin");
        let app_text = include_bytes!("../../../multiblock_batch.text");
        assert_eq!(app_bin.len(), 1_323_208);
        assert_eq!(app_text.len(), 1_193_676);
        assert_eq!(
            format!("{:x}", Sha256::digest(app_bin)),
            "3eab56f061f330704fc90da98c5c3de9aef824842873fc2eb240475da5945d4a"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(app_text)),
            "cd1c9b6679b97a47b24a71208d281b417a3cb714760fcf5b065896e6c6a84ce9"
        );
        assert_eq!(
            version.program_commitment.0,
            [
                220972078, 4003957755, 139804345, 3784237551, 2762571289, 2606609965, 2574444425,
                617776165,
            ]
        );
    }
}
