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

// SYSCOIN: Keep the zero sentinel rejection even after binding this isolated candidate
// to the reproducible guest and its successfully generated Security100 verification key.
const ZERO_VK_HASH: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";
pub const SYSCOIN_VK_HASH: &str =
    "0x8e6285da659dac3cfff56dbae3bf445e1524b9f08a9270f19d3361a97f8ce990";
const SYSCOIN_APP_MD5: &str = "22af69bc5729c261f3043fd0e5f1870a";
pub const SYSCOIN_PROGRAM_COMMITMENT: ProgramCommitment = ProgramCommitment([
    0xbf5be160, 0xcc4b6fff, 0x331c10d5, 0x91691e0c, 0x5f62df1b, 0xe058b2e0, 0xee9c8fc8, 0xc8640c66,
]);

/// SYSCOIN: The sole canonical lane is protocol V32, Execution V7, Proving V8.
/// It uses the patched zksync-os v0.4.0 app with compact Bitcoin DA.
const SYSCOIN_V32_EXECUTION_V7_PROVING_V8: ProtocolVersion = ProtocolVersion {
    // Keccak256 of the phase-3 SNARK VK (`generate-vk --check-aux-params`), so it binds the
    // app binary below. This candidate does not authorize release or deployment.
    vk_hash: VerificationKeyHash(SYSCOIN_VK_HASH),
    airbender_version: AirbenderVersion("V2"),
    zksync_os_version: ZkSyncOSVersion("v0.4.0"),
    zkos_wrapper: ZkOsWrapperVersion("V2-log22"),
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
        if version.program_commitment.0 == [0; 8] {
            return Err("Syscoin app-bound program commitment requires regeneration".to_owned());
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

    fn registered(&self) -> impl Iterator<Item = &ProtocolVersion> {
        self.versions
            .iter()
            .filter(|v| v.vk_hash.0 != ZERO_VK_HASH && v.program_commitment.0 != [0; 8])
    }

    /// Checks if the given VK hash is supported.
    pub fn contains(&self, vk_hash: &str) -> bool {
        self.registered().any(|v| v.vk_hash.0 == vk_hash)
    }

    /// Returns the list of supported VK hashes as strings.
    pub fn vk_hashes(&self) -> Vec<String> {
        self.registered()
            .map(|version| version.vk_hash.0.to_string())
            .collect()
    }

    /// SYSCOIN: The app-program commitment recorded for the version with this VK hash;
    /// `None` if the VK hash is unsupported.
    pub fn program_commitment_for(&self, vk_hash: &str) -> Option<ProgramCommitment> {
        self.registered()
            .find(|v| v.vk_hash.0 == vk_hash)
            .map(|v| v.program_commitment)
    }

    /// SYSCOIN: Checks the canonical lane's required app commitment without an unbound fallback.
    pub fn supports_program(&self, commitment: &ProgramCommitment) -> bool {
        self.registered()
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
        let mut versions = SupportedProtocolVersions::default();
        versions.versions[0].vk_hash = VerificationKeyHash(ZERO_VK_HASH);
        let error = versions
            .ensure_syscoin_release_constants()
            .expect_err("zero VK sentinel must keep the deployment gate closed");
        assert!(error.contains("zero regeneration sentinel"));
    }

    #[test]
    fn only_the_rebuilt_guest_lane_is_registered() {
        let versions = SupportedProtocolVersions::default();
        versions.ensure_syscoin_release_constants().unwrap();
        assert_eq!(versions.vk_hashes(), [SYSCOIN_VK_HASH]);
        assert_eq!(
            versions.program_commitment_for(SYSCOIN_VK_HASH),
            Some(SYSCOIN_PROGRAM_COMMITMENT)
        );
        assert!(versions.supports_program(&SYSCOIN_PROGRAM_COMMITMENT));
        assert!(!versions
            .contains("0x22b4a58c40ab11839bfc79c96957f24711776f3e1992fa3cf14c1c3b898a2153"));
        assert!(!versions.contains(ZERO_VK_HASH));
        for historical in [
            "0x9bb49673b5437ada0c0941bb7f35422456a5c7833dd8292bf17f29fe1e9baa97",
            "0x2ac3231439b0ba30b688a78eba0119fdfcf7a8364cf75037606cfb61f92c0b90",
            "0x229a4a5a7715fb19f8a5940e42d9cd53bb85f040bcf0f71c76612450fb8235b1",
            "0x62bd64130fba79809f37a652bc7957b87fa847fde30c4444d91fcf876357f144",
        ] {
            assert!(!versions.contains(historical));
            assert_eq!(versions.program_commitment_for(historical), None);
        }
        assert!(!versions.supports_program(&ProgramCommitment([
            0x08e47e45, 0x31d0dc34, 0x09c5ae1d, 0xb30b45bf, 0xec4b6189, 0x3c8444f4, 0x5f80e5c2,
            0x54d5bd94,
        ])));
        assert!(!versions
            .contains("0xd5bc91a7af04425e93a92ad4e29f4f9ab62210087b5dea105d6bb579f1218139"));
        assert!(!versions.supports_program(&ProgramCommitment([
            0x05c969ad, 0x8fcf8870, 0xcbb064c2, 0x947101ae, 0x27a5152c, 0x64467dcd, 0x7641f880,
            0x485131de,
        ])));
        assert!(!versions
            .contains("0x9f7576b911e7d3f528d49f894208682c81800814db9e3beac7fc3b1c4d626e7a"));
        // The previously qualified key/chain remain historical, not a second
        // supported lane after the circuit and shared PoW parameters changed.
        assert!(!versions
            .contains("0xc1ab3d6506620ad299672c2c2530e8732ac7bae55cdb9d8cf1fa12355b7388fe"));
        assert!(!versions.supports_program(&ProgramCommitment([
            0x1be0999e, 0xb16ad923, 0x5efc3c32, 0x0a750afa, 0x496f7ee4, 0xcb947492, 0x6decbd53,
            0x9eeea674,
        ])));
        assert!(!versions.supports_program(&ProgramCommitment([0; 8])));
    }

    #[test]
    fn canonical_app_constants_match_checked_in_syscoin_artifacts() {
        let versions = SupportedProtocolVersions::default();
        let [version] = versions.versions.as_slice() else {
            panic!("expected one canonical version")
        };
        assert_eq!(version.bin_md5sum.0, "22af69bc5729c261f3043fd0e5f1870a");
        let app_bin = include_bytes!("../../../multiblock_batch.bin");
        let app_text = include_bytes!("../../../multiblock_batch.text");
        assert_eq!(app_bin.len(), 1_329_572);
        assert_eq!(app_text.len(), 1_199_892);
        assert_eq!(
            format!("{:x}", Sha256::digest(app_bin)),
            "9727a6d5c1301bc0fdb9ef7b46027917aef51c9158a7678dec1287bffb9b3e4d"
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(app_text)),
            "4648aea720d7acb9317d90047b2640f85baacf15bfdfe340c21c03dc3984f932"
        );
        assert_eq!(version.program_commitment, SYSCOIN_PROGRAM_COMMITMENT);
    }
}
