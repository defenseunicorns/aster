use crate::model::NodeId;

/// Stable identifier for one complete, non-negotiable security profile.
///
/// Numeric values identify wire representations only. They do not define an
/// ordering or imply that one profile is stronger than another.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u16)]
pub enum SecurityProfileId {
    /// Historical Aster record protection: P-256 + ML-KEM-768 and
    /// ECDSA-P256 + ML-DSA-65.
    #[default]
    HybridPqAsterRecordV1 = 0x0001,
    /// Classical P-256 authentication bound to an authenticated Iroh QUIC
    /// carrier. Ordinary application records remain protected by that carrier.
    ClassicalP256IrohQuicV1 = 0x0002,
}

impl SecurityProfileId {
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0001 => Some(Self::HybridPqAsterRecordV1),
            0x0002 => Some(Self::ClassicalP256IrohQuicV1),
            _ => None,
        }
    }

    pub const fn as_u16(self) -> u16 {
        self as u16
    }
}

/// Stable profile ID for the existing hybrid suite. Existing encodings remain
/// byte-for-byte unchanged and continue to use this value.
pub const HYBRID_SECURITY_PROFILE_ID: u16 = SecurityProfileId::HybridPqAsterRecordV1 as u16;

/// Stable profile and complete-suite ID for the classical carrier-bound lane.
pub const CLASSICAL_SECURITY_PROFILE_ID: u16 = SecurityProfileId::ClassicalP256IrohQuicV1 as u16;
pub const CLASSICAL_SUITE_ID: u16 = CLASSICAL_SECURITY_PROFILE_ID;

/// Where ordinary post-handshake application bytes receive confidentiality
/// and integrity for a complete profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplicationProtection {
    /// Aster's `ASTRFR01` record layer is required.
    AsterRecordLayer,
    /// The already-authenticated carrier is required; Aster must not add its
    /// record layer to ordinary application bytes.
    AuthenticatedCarrierRequired,
}

/// Static, non-secret metadata for a complete security profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SecurityProfile {
    id: SecurityProfileId,
    suite_id: u16,
    receipt_label: &'static str,
    application_protection: ApplicationProtection,
    maximum_semantic_version: u16,
}

impl SecurityProfile {
    pub const HYBRID_PQ_ASTER_RECORD_V1: Self = Self {
        id: SecurityProfileId::HybridPqAsterRecordV1,
        suite_id: 0x0001,
        receipt_label: "hybrid-pq-aster-record-v1",
        application_protection: ApplicationProtection::AsterRecordLayer,
        maximum_semantic_version: 9,
    };

    pub const CLASSICAL_P256_IROH_QUIC_V1: Self = Self {
        id: SecurityProfileId::ClassicalP256IrohQuicV1,
        suite_id: CLASSICAL_SUITE_ID,
        receipt_label: "classical-p256-iroh-quic-v1",
        application_protection: ApplicationProtection::AuthenticatedCarrierRequired,
        maximum_semantic_version: 1,
    };

    pub const fn for_id(id: SecurityProfileId) -> Self {
        match id {
            SecurityProfileId::HybridPqAsterRecordV1 => Self::HYBRID_PQ_ASTER_RECORD_V1,
            SecurityProfileId::ClassicalP256IrohQuicV1 => Self::CLASSICAL_P256_IROH_QUIC_V1,
        }
    }

    pub const fn id(self) -> SecurityProfileId {
        self.id
    }

    pub const fn suite_id(self) -> u16 {
        self.suite_id
    }

    pub const fn receipt_label(self) -> &'static str {
        self.receipt_label
    }

    pub const fn application_protection(self) -> ApplicationProtection {
        self.application_protection
    }

    pub const fn maximum_semantic_version(self) -> u16 {
        self.maximum_semantic_version
    }
}

impl Default for SecurityProfile {
    fn default() -> Self {
        Self::HYBRID_PQ_ASTER_RECORD_V1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_profile_ceiling_matches_the_public_semantic_ceiling() {
        assert_eq!(
            SecurityProfile::HYBRID_PQ_ASTER_RECORD_V1.maximum_semantic_version(),
            crate::HIGHEST_SUPPORTED_SEMANTIC_VERSION
        );
        assert_eq!(
            SecurityProfile::CLASSICAL_P256_IROH_QUIC_V1.maximum_semantic_version(),
            1
        );
    }
}

/// Authority-authenticated receipt for the exact provisioned profile policy.
///
/// The current policy is deliberately singleton: `profile_id`,
/// `required_profile_id`, and the selected profile are equal. Numeric IDs are
/// never compared as a strength ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedSecurityProfile {
    profile_id: SecurityProfileId,
    required_profile_id: SecurityProfileId,
    suite_id: u16,
    policy_generation: u64,
    mission_principal: NodeId,
    policy_authority_id: NodeId,
}

impl VerifiedSecurityProfile {
    pub(super) const fn new_classical(
        policy_generation: u64,
        mission_principal: NodeId,
        policy_authority_id: NodeId,
    ) -> Self {
        Self {
            profile_id: SecurityProfileId::ClassicalP256IrohQuicV1,
            required_profile_id: SecurityProfileId::ClassicalP256IrohQuicV1,
            suite_id: CLASSICAL_SUITE_ID,
            policy_generation,
            mission_principal,
            policy_authority_id,
        }
    }

    pub const fn profile_id(self) -> SecurityProfileId {
        self.profile_id
    }

    pub const fn profile_id_u16(self) -> u16 {
        self.profile_id.as_u16()
    }

    pub const fn required_profile_id(self) -> SecurityProfileId {
        self.required_profile_id
    }

    pub const fn suite_id(self) -> u16 {
        self.suite_id
    }

    pub const fn policy_generation(self) -> u64 {
        self.policy_generation
    }

    pub const fn mission_principal(self) -> NodeId {
        self.mission_principal
    }

    pub const fn policy_authority_id(self) -> NodeId {
        self.policy_authority_id
    }

    pub const fn profile(self) -> SecurityProfile {
        SecurityProfile::CLASSICAL_P256_IROH_QUIC_V1
    }
}
