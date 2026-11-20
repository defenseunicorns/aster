//! Disposable, independently generated selected-node conflict/control fixture.
use aster_mesh::{
    Priority, ProvisioningAccess, RecordContentVerification, ReferenceEnvelopeSealer,
    ReferenceProvisioner, Scope, Topic,
};
use aster_node::mission::UnprotectedReferenceMission;
use aster_redb_store::Store;
use std::{error::Error, path::Path};

pub fn prepare(root: &Path) -> Result<(), Box<dyn Error>> {
    let topic = Topic::new("position.current")?;
    let scope = Scope::new("mission/team/alpha")?;
    let access = ProvisioningAccess::member(scope.clone(), vec![1], vec![topic.clone()])?;
    // Public test seed. No operational trust or credential material is read.
    let mut provisioner = ReferenceProvisioner::from_seed([0xa6; 32])?;
    let mut publishers = (1..=3)
        .map(|i| {
            provisioner
                .issue_node(i, std::slice::from_ref(&access))
                .and_then(ReferenceEnvelopeSealer::open)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let bundle = provisioner.issue_control_authority(10, std::slice::from_ref(&access))?;
    let encoded = bundle.to_bytes()?;
    let mut reader = ReferenceEnvelopeSealer::open(bundle)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root.join("state"))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(root.join("state"))?;
    UnprotectedReferenceMission::persist(root.join("mission.bundle"), encoded)?;
    std::fs::write(
        root.join("registry.public"),
        provisioner.export_rekey_registry()?,
    )?;
    std::fs::write(root.join("identity.public"), reader.identity())?;
    let store =
        Store::open_for_mission(root.join("state/mesh.redb"), reader.mission_authority_id())?;
    let policy = store.control_policy_snapshot()?;
    // Reserve all dots before committing any head, producing real concurrency.
    let reservations = publishers
        .iter()
        .map(|p| store.reserve_record_with_policy(&policy, p.identity(), &topic, &scope))
        .collect::<Result<Vec<_>, _>>()?;
    for (i, (publisher, reservation)) in publishers.iter_mut().zip(&reservations).enumerate() {
        let payload = if i == 2 {
            Vec::new()
        } else {
            format!("sibling-{i}").into_bytes()
        };
        let header = reservation.header(
            Priority::Priority,
            b"unit-7".to_vec(),
            payload.len() as u64,
            i == 2,
            1,
        )?;
        let sealed = publisher.seal_record(&header, &payload)?;
        let route = reader.verify_record(&sealed.bytes)?;
        let RecordContentVerification::ContentVerified { record, .. } =
            reader.verify_record_content(route, &sealed.bytes)?
        else {
            return Err("fixture reader lacks content authority".into());
        };
        store.commit_reserved_record_with_policy(&policy, reservation, &record, &sealed.bytes)?;
    }
    Ok(())
}
