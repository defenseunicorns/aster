use crate::ControllerFingerprint;
use std::{
    future::Future,
    io::Read,
    path::{Path, PathBuf},
    pin::Pin,
    process::Stdio,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const MAX_FINGERPRINT_INPUT_BYTES: usize = 64;
const MAX_SYSFS_LINK_BYTES: usize = 512;
const BLUEZ_VERSION_DEADLINE: Duration = Duration::from_millis(250);
const FINGERPRINT_COLLECTION_DEADLINE: Duration = Duration::from_millis(500);

pub(crate) type FingerprintFuture<'a> =
    Pin<Box<dyn Future<Output = Vec<ControllerFingerprint>> + Send + 'a>>;

pub(crate) trait ControllerFingerprintCollector: Send + Sync {
    fn collect<'a>(&'a self, adapter_names: &'a [String]) -> FingerprintFuture<'a>;
}

pub(crate) struct ProductionControllerFingerprintCollector {
    source: Arc<dyn FingerprintBatchSource>,
    in_flight: Arc<AtomicBool>,
    deadline: Duration,
}

trait FingerprintBatchSource: Send + Sync {
    fn collect(&self, adapter_names: &[String]) -> Vec<ControllerFingerprint>;
}

#[derive(Default)]
struct ProductionFingerprintBatchSource {
    system: OnceLock<SystemFingerprintInput>,
}

#[derive(Clone)]
struct SystemFingerprintInput {
    kernel: Option<Vec<u8>>,
    bluez: Option<Vec<u8>>,
}

impl Default for ProductionControllerFingerprintCollector {
    fn default() -> Self {
        Self {
            source: Arc::new(ProductionFingerprintBatchSource::default()),
            in_flight: Arc::new(AtomicBool::new(false)),
            deadline: FINGERPRINT_COLLECTION_DEADLINE,
        }
    }
}

impl ProductionControllerFingerprintCollector {
    #[cfg(test)]
    fn with_source_for_test(source: Arc<dyn FingerprintBatchSource>, deadline: Duration) -> Self {
        Self {
            source,
            in_flight: Arc::new(AtomicBool::new(false)),
            deadline,
        }
    }
}

impl FingerprintBatchSource for ProductionFingerprintBatchSource {
    fn collect(&self, adapter_names: &[String]) -> Vec<ControllerFingerprint> {
        let system = self.system.get_or_init(load_system_fingerprint).clone();
        adapter_names
            .iter()
            .map(|adapter_name| {
                let input = ProductionLinuxFingerprintInput {
                    kernel: system.kernel.clone(),
                    bluez: system.bluez.clone(),
                    sys_class_bluetooth: PathBuf::from("/sys/class/bluetooth"),
                };
                collect_production_linux_controller_fingerprint(&input, adapter_name)
            })
            .collect()
    }
}

impl ControllerFingerprintCollector for ProductionControllerFingerprintCollector {
    fn collect<'a>(&'a self, adapter_names: &'a [String]) -> FingerprintFuture<'a> {
        let count = adapter_names.len();
        let adapter_names = adapter_names.to_vec();
        let source = self.source.clone();
        let in_flight = self.in_flight.clone();
        let deadline = self.deadline;
        Box::pin(async move {
            if in_flight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                return empty_linux_fingerprints(count);
            }

            let (sender, receiver) = tokio::sync::oneshot::channel();
            let guard = InFlightGuard(in_flight);
            tokio::task::spawn_blocking(move || {
                let _guard = guard;
                let _ = sender.send(source.collect(&adapter_names));
            });
            match tokio::time::timeout(deadline, receiver).await {
                Ok(Ok(fingerprints)) if fingerprints.len() == count => fingerprints,
                _ => empty_linux_fingerprints(count),
            }
        })
    }
}

struct InFlightGuard(Arc<AtomicBool>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

trait LinuxFingerprintInput {
    fn kernel_release(&self) -> Option<Vec<u8>>;
    fn bluez_version(&self) -> Option<Vec<u8>>;
    fn controller_modalias(&self, adapter_name: &str) -> Option<Vec<u8>>;
    fn controller_driver(&self, adapter_name: &str) -> Option<Vec<u8>>;
    fn controller_firmware(&self, adapter_name: &str) -> Option<Vec<u8>>;
}

struct ProductionLinuxFingerprintInput {
    kernel: Option<Vec<u8>>,
    bluez: Option<Vec<u8>>,
    sys_class_bluetooth: PathBuf,
}

struct ObservedLinuxFingerprintInput {
    kernel: Option<Vec<u8>>,
    bluez: Option<Vec<u8>>,
    modalias: Option<Vec<u8>>,
    driver: Option<Vec<u8>>,
    firmware: Option<Vec<u8>>,
}

impl LinuxFingerprintInput for ObservedLinuxFingerprintInput {
    fn kernel_release(&self) -> Option<Vec<u8>> {
        self.kernel.clone()
    }

    fn bluez_version(&self) -> Option<Vec<u8>> {
        self.bluez.clone()
    }

    fn controller_modalias(&self, _adapter_name: &str) -> Option<Vec<u8>> {
        self.modalias.clone()
    }

    fn controller_driver(&self, _adapter_name: &str) -> Option<Vec<u8>> {
        self.driver.clone()
    }

    fn controller_firmware(&self, _adapter_name: &str) -> Option<Vec<u8>> {
        self.firmware.clone()
    }
}

struct ControllerIdentityInput {
    modalias: Option<Vec<u8>>,
    driver: Option<Vec<u8>>,
    firmware: Option<Vec<u8>>,
}

fn collect_production_linux_controller_fingerprint(
    input: &ProductionLinuxFingerprintInput,
    adapter_name: &str,
) -> ControllerFingerprint {
    collect_production_linux_controller_fingerprint_with_hook(input, adapter_name, || {})
}

fn collect_production_linux_controller_fingerprint_with_hook(
    input: &ProductionLinuxFingerprintInput,
    adapter_name: &str,
    after_modalias: impl FnOnce(),
) -> ControllerFingerprint {
    let identity = read_controller_identity(input, adapter_name, after_modalias);
    let observed = ObservedLinuxFingerprintInput {
        kernel: input.kernel.clone(),
        bluez: input.bluez.clone(),
        modalias: identity.as_ref().and_then(|value| value.modalias.clone()),
        driver: identity.as_ref().and_then(|value| value.driver.clone()),
        firmware: identity.and_then(|value| value.firmware),
    };
    collect_linux_controller_fingerprint(&observed, adapter_name)
}

fn collect_linux_controller_fingerprint(
    input: &impl LinuxFingerprintInput,
    adapter_name: &str,
) -> ControllerFingerprint {
    let kernel = bounded_atom(input.kernel_release());
    let bluez = bounded_atom(input.bluez_version());
    let modalias = bounded_atom(input.controller_modalias(adapter_name))
        .and_then(|value| value.parse::<bluer::Modalias>().ok());
    let vendor = modalias
        .as_ref()
        .map(|value| format!("{}:{:04x}", value.source.to_ascii_lowercase(), value.vendor));
    let product = modalias
        .as_ref()
        .map(|value| format!("{:04x}", value.product));
    let revision = modalias
        .as_ref()
        .map(|value| format!("{:04x}", value.device));
    let firmware = bounded_atom(input.controller_firmware(adapter_name));
    let driver = bounded_atom(input.controller_driver(adapter_name));

    ControllerFingerprint::new(
        Some(std::env::consts::OS),
        Some(std::env::consts::ARCH),
        kernel.as_deref(),
        bluez.as_deref(),
        vendor.as_deref(),
        product.as_deref(),
        revision.as_deref(),
        firmware.as_deref(),
        driver.as_deref(),
    )
}

fn empty_linux_fingerprint() -> ControllerFingerprint {
    ControllerFingerprint::new(
        Some(std::env::consts::OS),
        Some(std::env::consts::ARCH),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

fn empty_linux_fingerprints(count: usize) -> Vec<ControllerFingerprint> {
    std::iter::repeat_with(empty_linux_fingerprint)
        .take(count)
        .collect()
}

fn load_system_fingerprint() -> SystemFingerprintInput {
    const BLUETOOTHD_PATHS: [&str; 3] = [
        "/usr/sbin/bluetoothd",
        "/usr/libexec/bluetooth/bluetoothd",
        "/usr/lib/bluetooth/bluetoothd",
    ];

    SystemFingerprintInput {
        kernel: read_bounded_file(PathBuf::from("/proc/sys/kernel/osrelease")),
        bluez: BLUETOOTHD_PATHS
            .iter()
            .map(Path::new)
            .find_map(|path| read_command_version(path, BLUEZ_VERSION_DEADLINE)),
    }
}

fn bounded_atom(bytes: Option<Vec<u8>>) -> Option<String> {
    let bytes = bytes?;
    let value = std::str::from_utf8(&bytes).ok()?.trim_ascii_end();
    if value.is_empty()
        || value.len() > MAX_FINGERPRINT_INPUT_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'-' | b'_' | b'+' | b'~' | b':' | b'@')
        })
    {
        None
    } else {
        Some(value.to_owned())
    }
}

fn read_controller_identity(
    input: &ProductionLinuxFingerprintInput,
    adapter_name: &str,
    after_modalias: impl FnOnce(),
) -> Option<ControllerIdentityInput> {
    let device_path = controller_device(input, adapter_name)?;
    let device = std::fs::File::open(&device_path).ok()?;
    let device_metadata = device.metadata().ok()?;
    let modalias = read_bounded_at(&device, "modalias");
    after_modalias();
    let firmware = read_bounded_at(&device, "firmware_version")
        .or_else(|| read_bounded_at(&device, "firmware"));

    let driver = open_directory_at(&device, "driver");
    let driver_target = read_bounded_link_at(&device, "driver");
    let module = driver
        .as_ref()
        .and_then(|driver| open_directory_at(driver, "module"));
    let driver_version = module
        .as_ref()
        .and_then(|module| read_bounded_at(module, "version"));

    if modalias != read_bounded_at(&device, "modalias")
        || firmware
            != read_bounded_at(&device, "firmware_version")
                .or_else(|| read_bounded_at(&device, "firmware"))
        || driver_target != read_bounded_link_at(&device, "driver")
        || driver_version
            != module
                .as_ref()
                .and_then(|module| read_bounded_at(module, "version"))
    {
        return None;
    }

    let current_device = std::fs::File::open(device_path).ok()?;
    let current_driver = open_directory_at(&device, "driver");
    let current_module = current_driver
        .as_ref()
        .and_then(|driver| open_directory_at(driver, "module"));
    if !same_file(&device_metadata, &current_device.metadata().ok()?)
        || !same_optional_file(driver.as_ref(), current_driver.as_ref())
        || !same_optional_file(module.as_ref(), current_module.as_ref())
    {
        return None;
    }

    Some(ControllerIdentityInput {
        modalias,
        driver: combine_driver_identity(driver_target, driver_version),
        firmware,
    })
}

fn controller_device(
    input: &ProductionLinuxFingerprintInput,
    adapter_name: &str,
) -> Option<PathBuf> {
    let index = adapter_name.strip_prefix("hci")?;
    if index.is_empty() || !index.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    Some(input.sys_class_bluetooth.join(adapter_name).join("device"))
}

fn open_directory_at(directory: &std::fs::File, name: &str) -> Option<std::fs::File> {
    rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::DIRECTORY,
        rustix::fs::Mode::empty(),
    )
    .ok()
    .map(std::fs::File::from)
}

fn read_bounded_at(directory: &std::fs::File, name: &str) -> Option<Vec<u8>> {
    let file = rustix::fs::openat(
        directory,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )
    .ok()?;
    read_bounded(std::fs::File::from(file))
}

fn read_bounded_link_at(directory: &std::fs::File, name: &str) -> Option<Vec<u8>> {
    let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); MAX_SYSFS_LINK_BYTES + 1];
    let (initialized, remaining) = rustix::fs::readlinkat_raw(directory, name, &mut buffer).ok()?;
    if remaining.is_empty() || initialized.len() > MAX_SYSFS_LINK_BYTES {
        None
    } else {
        Some(initialized.to_vec())
    }
}

fn same_optional_file(left: Option<&std::fs::File>, right: Option<&std::fs::File>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => match (left.metadata(), right.metadata()) {
            (Ok(left), Ok(right)) => same_file(&left, &right),
            _ => false,
        },
        (None, None) => true,
        _ => false,
    }
}

fn same_file(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    left.dev() == right.dev() && left.ino() == right.ino()
}

fn combine_driver_identity(target: Option<Vec<u8>>, version: Option<Vec<u8>>) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt as _;

    let target = target?;
    let name = Path::new(std::ffi::OsStr::from_bytes(&target))
        .file_name()?
        .as_bytes()
        .to_vec();
    let Some(version) = version else {
        return Some(name);
    };
    let name = bounded_atom(Some(name))?;
    let version = bounded_atom(Some(version))?;
    Some(format!("{name}@{version}").into_bytes())
}

fn read_bounded_file(path: PathBuf) -> Option<Vec<u8>> {
    read_bounded(std::fs::File::open(path).ok()?)
}

fn read_bounded(mut file: std::fs::File) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(MAX_FINGERPRINT_INPUT_BYTES + 1);
    file.by_ref()
        .take((MAX_FINGERPRINT_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    Some(bytes)
}

fn read_command_version(program: &Path, deadline: Duration) -> Option<Vec<u8>> {
    use std::os::unix::process::CommandExt as _;

    let mut command = std::process::Command::new(program);
    command
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn().ok()?;
    let mut stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            terminate_command(&mut child);
            return None;
        }
    };
    let flags = match rustix::fs::fcntl_getfl(&stdout) {
        Ok(flags) => flags,
        Err(_) => {
            terminate_command(&mut child);
            return None;
        }
    };
    if rustix::fs::fcntl_setfl(&stdout, flags | rustix::fs::OFlags::NONBLOCK).is_err() {
        terminate_command(&mut child);
        return None;
    }

    let mut retained = Vec::with_capacity(MAX_FINGERPRINT_INPUT_BYTES + 1);
    let mut buffer = [0_u8; 256];
    let mut status = None;
    let mut eof = false;
    let expires = std::time::Instant::now() + deadline;
    loop {
        while !eof {
            match stdout.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(read) => {
                    let remaining = MAX_FINGERPRINT_INPUT_BYTES
                        .saturating_add(1)
                        .saturating_sub(retained.len());
                    retained.extend_from_slice(&buffer[..read.min(remaining)]);
                    if read > remaining || retained.len() > MAX_FINGERPRINT_INPUT_BYTES {
                        terminate_command(&mut child);
                        return None;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    terminate_command(&mut child);
                    return None;
                }
            }
        }
        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(_) => {
                    terminate_command(&mut child);
                    return None;
                }
            };
        }
        if let Some(status) = status
            && eof
        {
            return status.success().then_some(retained);
        }
        let now = std::time::Instant::now();
        if now >= expires {
            terminate_command(&mut child);
            return None;
        }
        std::thread::sleep((expires - now).min(Duration::from_millis(5)));
    }
}

fn terminate_command(child: &mut std::process::Child) {
    if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ControllerAdmissionPolicy, ControllerFingerprint, ControllerSupportRow,
        ControllerUnsafeRule, ProbeDisposition, ProbeReason, SupportTag,
    };
    use std::path::PathBuf;

    struct BlockingFingerprintSource {
        calls: Arc<std::sync::atomic::AtomicUsize>,
        release: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    }

    impl FingerprintBatchSource for BlockingFingerprintSource {
        fn collect(&self, adapter_names: &[String]) -> Vec<ControllerFingerprint> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (lock, changed) = &*self.release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = changed.wait(released).unwrap();
            }
            adapter_names
                .iter()
                .map(|_| empty_linux_fingerprint())
                .collect()
        }
    }

    struct TestFingerprintInput {
        kernel: Option<Vec<u8>>,
        bluez: Option<Vec<u8>>,
        modalias: Option<Vec<u8>>,
        driver: Option<Vec<u8>>,
        firmware: Option<Vec<u8>>,
    }

    impl LinuxFingerprintInput for TestFingerprintInput {
        fn kernel_release(&self) -> Option<Vec<u8>> {
            self.kernel.clone()
        }

        fn bluez_version(&self) -> Option<Vec<u8>> {
            self.bluez.clone()
        }

        fn controller_modalias(&self, _adapter_name: &str) -> Option<Vec<u8>> {
            self.modalias.clone()
        }

        fn controller_driver(&self, _adapter_name: &str) -> Option<Vec<u8>> {
            self.driver.clone()
        }

        fn controller_firmware(&self, _adapter_name: &str) -> Option<Vec<u8>> {
            self.firmware.clone()
        }
    }

    #[test]
    fn bounded_linux_observation_can_match_one_exact_support_row() {
        let input = TestFingerprintInput {
            kernel: Some(b"6.8.12-1021-tegra\n".to_vec()),
            bluez: Some(b"5.72\n".to_vec()),
            modalias: Some(b"usb:v13D3p3549d0000dcE0dsc01dp01icE0isc01ip01in00\n".to_vec()),
            driver: Some(b"rtk_btusb@3.1.65ab490.20240531-141726\n".to_vec()),
            firmware: Some(b"rtl8852be-20240531\n".to_vec()),
        };
        let observed = collect_linux_controller_fingerprint(&input, "hci0");
        let expected = ControllerFingerprint::new(
            Some(std::env::consts::OS),
            Some(std::env::consts::ARCH),
            Some("6.8.12-1021-tegra"),
            Some("5.72"),
            Some("usb:13d3"),
            Some("3549"),
            Some("0000"),
            Some("rtl8852be-20240531"),
            Some("rtk_btusb@3.1.65ab490.20240531-141726"),
        );
        let policy = ControllerAdmissionPolicy::new(
            false,
            vec![ControllerSupportRow::exact(expected)],
            vec![],
        );

        assert_eq!(policy.admit(&observed).support(), SupportTag::Qualified);
    }

    #[test]
    fn malformed_or_oversized_observation_stays_unqualified() {
        let input = TestFingerprintInput {
            kernel: Some(vec![b'k'; 65]),
            bluez: Some(b"5.72\nforged".to_vec()),
            modalias: Some(b"usb:not-a-modalias".to_vec()),
            driver: Some(vec![0xff; 8]),
            firmware: Some(vec![b'f'; 65]),
        };
        let observed = collect_linux_controller_fingerprint(&input, "hci0");
        let complete = ControllerFingerprint::new(
            Some(std::env::consts::OS),
            Some(std::env::consts::ARCH),
            Some("6.8.12"),
            Some("5.72"),
            Some("usb:13d3"),
            Some("3549"),
            Some("0000"),
            Some("firmware"),
            Some("driver"),
        );
        let policy = ControllerAdmissionPolicy::new(
            false,
            vec![ControllerSupportRow::exact(complete)],
            vec![],
        );

        assert_eq!(policy.admit(&observed).support(), SupportTag::Unqualified);
    }

    #[tokio::test]
    async fn collection_timeout_is_nonfatal_and_single_flight() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let release = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let collector = ProductionControllerFingerprintCollector::with_source_for_test(
            Arc::new(BlockingFingerprintSource {
                calls: calls.clone(),
                release: release.clone(),
            }),
            Duration::from_millis(25),
        );
        let adapters = vec!["hci0".to_owned(), "hci1".to_owned()];

        let first = collector.collect(&adapters).await;
        let second = tokio::time::timeout(Duration::from_millis(10), collector.collect(&adapters))
            .await
            .expect("busy collection returns without starting another worker");

        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 2);
        assert!(first.iter().all(|fingerprint| {
            ControllerAdmissionPolicy::default()
                .admit(fingerprint)
                .support()
                == SupportTag::Unqualified
        }));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

        let (lock, changed) = &*release;
        *lock.lock().unwrap() = true;
        changed.notify_all();
    }

    #[test]
    fn production_input_reads_only_bounded_controller_identity() {
        struct Fixture(PathBuf);

        impl Drop for Fixture {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).expect("fingerprint fixture cleanup");
            }
        }

        static SEQUENCE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "aster-btle-fingerprint-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let fixture = Fixture(root);
        let device = fixture.0.join("hci0/device");
        let driver = fixture.0.join("drivers/rtk_btusb");
        let module = fixture.0.join("modules/rtk_btusb");
        std::fs::create_dir_all(&device).unwrap();
        std::fs::create_dir_all(&driver).unwrap();
        std::fs::create_dir_all(&module).unwrap();
        std::os::unix::fs::symlink(&driver, device.join("driver")).unwrap();
        std::os::unix::fs::symlink(&module, driver.join("module")).unwrap();
        std::fs::write(
            device.join("modalias"),
            b"usb:v13D3p3549d0000dcE0dsc01dp01icE0isc01ip01in00\n",
        )
        .unwrap();
        std::fs::write(device.join("firmware_version"), b"rtl8852be-20240531\n").unwrap();
        std::fs::write(module.join("version"), b"3.1.65ab490.20240531-141726\n").unwrap();

        let input = ProductionLinuxFingerprintInput {
            kernel: Some(b"6.8.12-1021-tegra\n".to_vec()),
            bluez: Some(b"5.72\n".to_vec()),
            sys_class_bluetooth: fixture.0.clone(),
        };
        let observed = collect_production_linux_controller_fingerprint(&input, "hci0");
        let expected = ControllerFingerprint::new(
            Some(std::env::consts::OS),
            Some(std::env::consts::ARCH),
            Some("6.8.12-1021-tegra"),
            Some("5.72"),
            Some("usb:13d3"),
            Some("3549"),
            Some("0000"),
            Some("rtl8852be-20240531"),
            Some("rtk_btusb@3.1.65ab490.20240531-141726"),
        );
        let policy = ControllerAdmissionPolicy::new(
            false,
            vec![ControllerSupportRow::exact(expected)],
            vec![],
        );

        assert_eq!(policy.admit(&observed).support(), SupportTag::Qualified);
    }

    #[test]
    fn controller_replacement_discards_all_hardware_identity() {
        struct Fixture(PathBuf);

        impl Drop for Fixture {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).expect("fingerprint fixture cleanup");
            }
        }

        static SEQUENCE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "aster-btle-fingerprint-replace-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let fixture = Fixture(root);
        let adapter = fixture.0.join("hci0");
        let first = fixture.0.join("devices/first");
        let second = fixture.0.join("devices/second");
        let driver = fixture.0.join("drivers/rtk_btusb");
        let module = fixture.0.join("modules/rtk_btusb");
        for path in [&adapter, &first, &second, &driver, &module] {
            std::fs::create_dir_all(path).unwrap();
        }
        std::os::unix::fs::symlink(&first, adapter.join("device")).unwrap();
        for (device, product) in [(&first, "3549"), (&second, "3550")] {
            std::fs::write(
                device.join("modalias"),
                format!("usb:v13D3p{product}d0000dcE0dsc01dp01icE0isc01ip01in00\n"),
            )
            .unwrap();
            std::fs::write(device.join("firmware_version"), b"rtl8852be-20240531\n").unwrap();
            std::os::unix::fs::symlink(&driver, device.join("driver")).unwrap();
        }
        std::os::unix::fs::symlink(&module, driver.join("module")).unwrap();
        std::fs::write(module.join("version"), b"3.1.65ab490.20240531-141726\n").unwrap();

        let input = ProductionLinuxFingerprintInput {
            kernel: Some(b"6.8.12-1021-tegra\n".to_vec()),
            bluez: Some(b"5.72\n".to_vec()),
            sys_class_bluetooth: fixture.0.clone(),
        };
        let first_link = adapter.join("device");
        let observed =
            collect_production_linux_controller_fingerprint_with_hook(&input, "hci0", || {
                std::fs::remove_file(&first_link).unwrap();
                std::os::unix::fs::symlink(&second, &first_link).unwrap();
            });
        let first_fingerprint = ControllerFingerprint::new(
            Some(std::env::consts::OS),
            Some(std::env::consts::ARCH),
            Some("6.8.12-1021-tegra"),
            Some("5.72"),
            Some("usb:13d3"),
            Some("3549"),
            Some("0000"),
            Some("rtl8852be-20240531"),
            Some("rtk_btusb@3.1.65ab490.20240531-141726"),
        );
        let policy = ControllerAdmissionPolicy::new(
            false,
            vec![ControllerSupportRow::exact(first_fingerprint.clone())],
            vec![ControllerUnsafeRule::exact(first_fingerprint)],
        );
        let admission = policy.admit(&observed);

        assert_eq!(admission.support(), SupportTag::Unqualified);
        assert_eq!(
            admission.disposition(),
            ProbeDisposition::Blocked(ProbeReason::AmbiguousUnsafeOverlap)
        );
    }

    #[test]
    fn version_command_returns_one_bounded_atom() {
        let script = version_script("printf '5.72\\n'");

        assert_eq!(
            read_command_version(&script.0, std::time::Duration::from_millis(100)),
            Some(b"5.72\n".to_vec())
        );
    }

    #[test]
    fn version_command_rejects_oversized_output() {
        let script = version_script("printf '%065d' 0");

        assert_eq!(
            read_command_version(&script.0, std::time::Duration::from_millis(100)),
            None
        );
    }

    #[test]
    fn version_command_is_killed_at_its_deadline() {
        let script = version_script("sleep 2");
        let started = std::time::Instant::now();

        assert_eq!(
            read_command_version(&script.0, std::time::Duration::from_millis(25)),
            None
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn version_command_deadline_includes_inherited_stdout() {
        let descendant_pid = unique_temp_path("aster-btle-descendant");
        let script = version_script(&format!(
            "sleep 2 & descendant=$!; printf '%s\\n' \"$descendant\" > {}; printf '5.72\\n'",
            descendant_pid.display()
        ));
        let started = std::time::Instant::now();

        assert_eq!(
            read_command_version(&script.0, std::time::Duration::from_millis(25)),
            None
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));

        let pid = std::fs::read_to_string(&descendant_pid)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        let process = PathBuf::from(format!("/proc/{pid}"));
        let expires = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while process.exists() && std::time::Instant::now() < expires {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(!process.exists(), "command descendant survived cleanup");
        std::fs::remove_file(descendant_pid).unwrap();
    }

    fn version_script(body: &str) -> ScriptFixture {
        use std::os::unix::fs::PermissionsExt as _;

        let path = unique_temp_path("aster-btle-version");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();
        ScriptFixture(path)
    }

    fn unique_temp_path(prefix: &str) -> PathBuf {
        static SEQUENCE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ))
    }

    struct ScriptFixture(PathBuf);

    impl Drop for ScriptFixture {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).expect("version script cleanup");
        }
    }
}
