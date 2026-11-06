use crate::utils::{IPAD, OPAD, get_der_key};
use core::{fmt, slice};
#[cfg(feature = "zeroize")]
use digest::zeroize::{Zeroize, Zeroizing};
use digest::{
    InvalidLength, KeyInit, MacMarker, Output, Reset,
    block_api::{
        AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, EagerHash, FixedOutputCore,
        OutputSizeUser, UpdateCore,
    },
    block_buffer::Eager,
    common::{Key, KeySizeUser},
};

struct DerivedKeyBlock<D: EagerHash>(Block<D::Core>);

#[cfg(all(test, feature = "zeroize"))]
mod drop_observer {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    pub(super) static ENABLED: AtomicBool = AtomicBool::new(false);
    pub(super) static PANIC_AFTER_CONSTRUCTION: AtomicBool = AtomicBool::new(false);
    pub(super) static ZEROIZED: AtomicUsize = AtomicUsize::new(0);
    pub(super) static NOT_ZEROIZED: AtomicUsize = AtomicUsize::new(0);

    pub(super) fn reset() {
        ZEROIZED.store(0, Ordering::Release);
        NOT_ZEROIZED.store(0, Ordering::Release);
        PANIC_AFTER_CONSTRUCTION.store(false, Ordering::Release);
        ENABLED.store(true, Ordering::Release);
    }
}

impl<D: EagerHash> DerivedKeyBlock<D> {
    fn block(&self) -> &Block<D::Core> {
        &self.0
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}

#[cfg(feature = "zeroize")]
impl<D: EagerHash> Zeroize for DerivedKeyBlock<D> {
    fn zeroize(&mut self) {
        self.bytes_mut().zeroize();
    }
}

#[cfg(all(test, feature = "zeroize"))]
impl<D: EagerHash> Drop for DerivedKeyBlock<D> {
    fn drop(&mut self) {
        use core::sync::atomic::Ordering;

        if drop_observer::ENABLED.load(Ordering::Acquire) {
            let counter = if self.0.iter().all(|byte| *byte == 0) {
                &drop_observer::ZEROIZED
            } else {
                &drop_observer::NOT_ZEROIZED
            };
            counter.fetch_add(1, Ordering::AcqRel);
        }
    }
}

#[cfg(feature = "zeroize")]
type ProtectedDerivedKey<D> = Zeroizing<DerivedKeyBlock<D>>;
#[cfg(not(feature = "zeroize"))]
type ProtectedDerivedKey<D> = DerivedKeyBlock<D>;

#[cfg(feature = "zeroize")]
fn protected_derived_key<D: EagerHash>(key: &[u8]) -> ProtectedDerivedKey<D> {
    Zeroizing::new(DerivedKeyBlock(get_der_key::<D>(key)))
}

#[cfg(not(feature = "zeroize"))]
fn protected_derived_key<D: EagerHash>(key: &[u8]) -> ProtectedDerivedKey<D> {
    DerivedKeyBlock(get_der_key::<D>(key))
}

#[cfg(all(test, feature = "zeroize"))]
fn inject_constructor_unwind() {
    use core::sync::atomic::Ordering;

    assert!(
        !drop_observer::PANIC_AFTER_CONSTRUCTION.swap(false, Ordering::AcqRel),
        "injected constructor unwind"
    );
}

/// Generic core HMAC instance, which operates over blocks.
pub struct HmacCore<D: EagerHash> {
    digest: D::Core,
    opad_digest: D::Core,
}

impl<D: EagerHash> Clone for HmacCore<D> {
    fn clone(&self) -> Self {
        Self {
            digest: self.digest.clone(),
            opad_digest: self.opad_digest.clone(),
        }
    }
}

impl<D: EagerHash> MacMarker for HmacCore<D> {}

impl<D: EagerHash> BufferKindUser for HmacCore<D> {
    type BufferKind = Eager;
}

impl<D: EagerHash> KeySizeUser for HmacCore<D> {
    type KeySize = <<D as EagerHash>::Core as BlockSizeUser>::BlockSize;
}

impl<D: EagerHash> BlockSizeUser for HmacCore<D> {
    type BlockSize = <<D as EagerHash>::Core as BlockSizeUser>::BlockSize;
}

impl<D: EagerHash> OutputSizeUser for HmacCore<D> {
    type OutputSize = <<D as EagerHash>::Core as OutputSizeUser>::OutputSize;
}

impl<D: EagerHash> KeyInit for HmacCore<D> {
    #[inline(always)]
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key.as_slice()).expect("HMAC accepts keys of any length")
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        let mut buf = protected_derived_key::<D>(key);
        #[cfg(all(test, feature = "zeroize"))]
        inject_constructor_unwind();
        buf.bytes_mut().iter_mut().for_each(|b| *b ^= IPAD);

        let mut digest = D::Core::default();
        digest.update_blocks(slice::from_ref(buf.block()));

        buf.bytes_mut().iter_mut().for_each(|b| *b ^= IPAD ^ OPAD);

        let mut opad_digest = D::Core::default();
        opad_digest.update_blocks(slice::from_ref(buf.block()));

        Ok(Self {
            opad_digest,
            digest,
        })
    }
}

impl<D: EagerHash> UpdateCore for HmacCore<D> {
    #[inline(always)]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.digest.update_blocks(blocks);
    }
}

impl<D: EagerHash> FixedOutputCore for HmacCore<D> {
    #[inline(always)]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let mut hash = Output::<D::Core>::default();
        self.digest.finalize_fixed_core(buffer, &mut hash);
        // finalize_fixed_core should reset the buffer as well, but
        // to be extra safe we reset it explicitly again.
        buffer.reset();
        let h = &mut self.opad_digest;
        buffer.digest_blocks(&hash, |b| h.update_blocks(b));
        h.finalize_fixed_core(buffer, out);
    }
}

impl<D: EagerHash + AlgorithmName> AlgorithmName for HmacCore<D> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hmac<")?;
        <D as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<D: EagerHash> fmt::Debug for HmacCore<D>
where
    D::Core: AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacCore { ... }")
    }
}

/// Generic core HMAC instance, which operates over blocks.
pub struct HmacResetCore<D: EagerHash> {
    digest: D::Core,
    opad_digest: D::Core,
    ipad_digest: D::Core,
}

impl<D: EagerHash> Clone for HmacResetCore<D> {
    fn clone(&self) -> Self {
        Self {
            digest: self.digest.clone(),
            opad_digest: self.opad_digest.clone(),
            ipad_digest: self.ipad_digest.clone(),
        }
    }
}

impl<D: EagerHash> MacMarker for HmacResetCore<D> {}

impl<D: EagerHash> BufferKindUser for HmacResetCore<D> {
    type BufferKind = Eager;
}

impl<D: EagerHash> KeySizeUser for HmacResetCore<D> {
    type KeySize = <<D as EagerHash>::Core as BlockSizeUser>::BlockSize;
}

impl<D: EagerHash> BlockSizeUser for HmacResetCore<D> {
    type BlockSize = <<D as EagerHash>::Core as BlockSizeUser>::BlockSize;
}

impl<D: EagerHash> OutputSizeUser for HmacResetCore<D> {
    type OutputSize = <<D as EagerHash>::Core as OutputSizeUser>::OutputSize;
}

impl<D: EagerHash> KeyInit for HmacResetCore<D> {
    #[inline(always)]
    fn new(key: &Key<Self>) -> Self {
        Self::new_from_slice(key.as_slice()).expect("HMAC accepts keys of any length")
    }

    #[inline(always)]
    fn new_from_slice(key: &[u8]) -> Result<Self, InvalidLength> {
        let mut buf = protected_derived_key::<D>(key);
        #[cfg(all(test, feature = "zeroize"))]
        inject_constructor_unwind();
        buf.bytes_mut().iter_mut().for_each(|b| *b ^= IPAD);

        let mut digest = D::Core::default();
        digest.update_blocks(slice::from_ref(buf.block()));

        buf.bytes_mut().iter_mut().for_each(|b| *b ^= IPAD ^ OPAD);

        let mut opad_digest = D::Core::default();
        opad_digest.update_blocks(slice::from_ref(buf.block()));

        Ok(Self {
            ipad_digest: digest.clone(),
            opad_digest,
            digest,
        })
    }
}

impl<D: EagerHash> UpdateCore for HmacResetCore<D> {
    #[inline(always)]
    fn update_blocks(&mut self, blocks: &[Block<Self>]) {
        self.digest.update_blocks(blocks);
    }
}

impl<D: EagerHash> FixedOutputCore for HmacResetCore<D> {
    #[inline(always)]
    fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
        let mut hash = Output::<D::Core>::default();
        self.digest.finalize_fixed_core(buffer, &mut hash);
        // finalize_fixed_core should reset the buffer as well, but
        // to be extra safe we reset it explicitly again.
        buffer.reset();
        let mut h = self.opad_digest.clone();
        buffer.digest_blocks(&hash, |b| h.update_blocks(b));
        h.finalize_fixed_core(buffer, out);
    }
}

impl<D: EagerHash> Reset for HmacResetCore<D> {
    #[inline(always)]
    fn reset(&mut self) {
        self.digest = self.ipad_digest.clone();
    }
}

impl<D: EagerHash + AlgorithmName> AlgorithmName for HmacResetCore<D> {
    fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hmac<")?;
        <D as AlgorithmName>::write_alg_name(f)?;
        f.write_str(">")
    }
}

impl<D: EagerHash> fmt::Debug for HmacResetCore<D>
where
    D::Core: AlgorithmName,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HmacResetCore { ... }")
    }
}

#[cfg(all(test, feature = "zeroize"))]
mod aster_tests {
    extern crate std;

    use super::*;
    use core::sync::atomic::Ordering;
    use std::{panic, sync::Mutex};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn assert_one_zeroized_drop() {
        assert_eq!(drop_observer::ZEROIZED.load(Ordering::Acquire), 1);
        assert_eq!(drop_observer::NOT_ZEROIZED.load(Ordering::Acquire), 0);
        drop_observer::ENABLED.store(false, Ordering::Release);
    }

    #[test]
    fn derived_key_is_zeroized_after_both_constructors_return() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        drop_observer::reset();
        HmacCore::<sha2::Sha256>::new_from_slice(b"normal-return")
            .expect("fixed key length is valid");
        assert_one_zeroized_drop();

        drop_observer::reset();
        HmacResetCore::<sha2::Sha256>::new_from_slice(b"normal-return")
            .expect("fixed key length is valid");
        assert_one_zeroized_drop();
    }

    #[test]
    fn derived_key_is_zeroized_when_both_constructors_unwind() {
        let _guard = TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        drop_observer::reset();
        drop_observer::PANIC_AFTER_CONSTRUCTION.store(true, Ordering::Release);
        assert!(panic::catch_unwind(|| {
            let _ = HmacCore::<sha2::Sha256>::new_from_slice(b"unwind");
        })
        .is_err());
        assert_one_zeroized_drop();

        drop_observer::reset();
        drop_observer::PANIC_AFTER_CONSTRUCTION.store(true, Ordering::Release);
        assert!(panic::catch_unwind(|| {
            let _ = HmacResetCore::<sha2::Sha256>::new_from_slice(b"unwind");
        })
        .is_err());
        assert_one_zeroized_drop();
    }
}
