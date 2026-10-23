//! Transport-neutral projection of native Profile-5 pack progress.

/// Receiver-local progress projected from the native pack checkpoint journal.
///
/// The pack and its alternating checkpoint files remain the durable authority;
/// this value is an in-memory status projection and creates no redb receipt row.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlobStreamResume {
    generation: u64,
    next_segment_index: u64,
    durable_plaintext_offset: u64,
    durable_pack_len: u64,
    durable_wire_offset: u64,
}

impl BlobStreamResume {
    pub const fn generation(self) -> u64 {
        self.generation
    }

    pub const fn next_segment_index(self) -> u64 {
        self.next_segment_index
    }

    pub const fn durable_plaintext_offset(self) -> u64 {
        self.durable_plaintext_offset
    }

    pub const fn durable_pack_len(self) -> u64 {
        self.durable_pack_len
    }

    pub const fn durable_wire_offset(self) -> u64 {
        self.durable_wire_offset
    }
}
