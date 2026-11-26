use super::*;

const INVALID_REPLACEMENT: &[u8] = b"not a redb database";

// Run once, after the descriptor has passed validation but before redb opens.
fn replace_after_validation(file: &TestFile) -> TestFile {
    let retained = TestFile::new("read-only-retained-original");
    let path = file.0.clone();
    let retained_path = retained.0.clone();
    READ_ONLY_BACKING_TEST_HOOK.set(Some(Box::new(move || {
        std::fs::rename(&path, &retained_path).expect("retain validated inode");
        std::fs::write(&path, INVALID_REPLACEMENT).expect("replace pathname");
    })));
    retained
}

#[test]
fn preflight_does_not_read_replacement_before_rejecting_path_change() {
    preflight_replacement(false);
}

#[test]
fn unclean_preflight_copies_validated_original_after_path_change() {
    preflight_replacement(true);
}

fn preflight_replacement(unclean: bool) {
    let file = TestFile::new("read-only-preflight-replacement");
    if unclean {
        run_abrupt_store_child(&file, "live");
        assert!(matches!(
            redb::Builder::new().open_read_only(&file.0),
            Err(redb::DatabaseError::RepairAborted)
        ));
    } else {
        drop(Store::open(&file.0).expect("create store"));
    }
    let before = std::fs::read(&file.0).unwrap();
    let retained = replace_after_validation(&file);

    let error = Store::require_numbered_publication_compatible(&file.0)
        .expect_err("reject changed pathname");
    assert!(
        matches!(
            error,
            StoreError::StoreBackingInvariant("publication preflight backing identity changed")
        ),
        "read or copied the unchecked replacement: {error:?}"
    );
    assert_eq!(std::fs::read(&retained.0).unwrap(), before);
    assert_eq!(std::fs::read(&file.0).unwrap(), INVALID_REPLACEMENT);
}

#[test]
fn readers_preserve_writer_exclusion_and_error_mapping() {
    let file = TestFile::new("read-only-writer-exclusion");
    let writer = Store::open_for_mission(&file.0, [0xa6; 32]).unwrap();
    for result in [
        Store::require_numbered_publication_compatible(&file.0),
        Store::inspect_existing(&file.0).map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(StoreError::Backend(redb::Error::DatabaseAlreadyOpen))
        ));
    }
    drop(writer);
    let before = std::fs::read(&file.0).unwrap();
    let backing = open_read_only_store_backing(&file.0).unwrap();
    let reader = redb::Builder::new()
        .open_read_only_with_backend(FileBackend::new(backing.file).unwrap())
        .unwrap();
    Store::inspect_existing(&file.0).expect("independent nested reader");
    Store::require_numbered_publication_compatible(&file.0).expect("nested preflight");
    assert!(matches!(
        Database::open(&file.0),
        Err(redb::DatabaseError::DatabaseAlreadyOpen)
    ));
    drop(reader);
    assert_eq!(std::fs::read(&file.0).unwrap(), before);
    drop(Database::open(&file.0).expect("writer after all readers close"));
}

#[test]
fn inspection_does_not_read_replacement_before_rejecting_path_change() {
    let file = TestFile::new("read-only-inspection-replacement");
    drop(Store::open(&file.0).expect("create store"));
    let before = std::fs::read(&file.0).unwrap();
    let retained = replace_after_validation(&file);

    let error = Store::inspect_existing(&file.0).expect_err("reject changed pathname");
    // A path-based redb open fails on the replacement's bytes instead of reaching
    // the identity check. Merely asserting any error would miss that read.
    assert!(
        matches!(
            error,
            StoreError::StoreBackingInvariant("backing path changed during read-only inspection")
        ),
        "read the unchecked replacement: {error:?}"
    );
    assert_eq!(std::fs::read(&retained.0).unwrap(), before);
    assert_eq!(std::fs::read(&file.0).unwrap(), INVALID_REPLACEMENT);
}
