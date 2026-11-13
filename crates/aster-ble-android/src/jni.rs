#![allow(unsafe_code)]

use crate::{
    PhaseSink, RunId, RunOutcome, RunRegistry, SessionEvent, ValidationReceipt, ValidatorConfig,
    ValidatorError, ValidatorErrorCategory, ValidatorPhase,
    session::{PreparationControl, prepare_local_event_cancellable},
};
use jni::{
    Env, EnvUnowned, JValue, JavaVM, jni_sig, jni_str,
    objects::{JCharArray, JClass, JObject, JString},
    refs::Global,
    sys::{jboolean, jint, jlong},
};
use std::{
    os::fd::{FromRawFd, OwnedFd},
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

const PREPARATION_THREAD_NAME: &str = "aster-event-prepare";
// Full node/store preparation normally runs on Linux's conventional 8 MiB
// stack, also used by the repository's full-node native tests. Android's
// JVM-created executor threads are smaller. Only one preparation can be active,
// so this is a fixed per-active-operation virtual-memory bound rather than an
// input-scaled allocation.
const PREPARATION_STACK_BYTES: usize = 8 * 1024 * 1024;

trait NativeCallback: Send + Sync + 'static {
    fn phase(&self, phase: ValidatorPhase) -> Result<(), ()>;
    fn complete(&self, receipt: &ValidationReceipt) -> Result<(), ()>;
    fn error(&self, category: ValidatorErrorCategory, message: &str) -> Result<(), ()>;
}

trait CancelTarget: Send + Sync + 'static {
    fn cancel(&self, id: RunId);
}

impl CancelTarget for RunRegistry {
    fn cancel(&self, id: RunId) {
        let _ = RunRegistry::cancel(self, id);
    }
}

struct CallbackState {
    run_id: Option<RunId>,
    cancel_pending: bool,
}

struct CallbackSink {
    callback: Arc<dyn NativeCallback>,
    canceller: Arc<dyn CancelTarget>,
    state: Mutex<CallbackState>,
    callback_failed: AtomicBool,
    terminal_delivered: AtomicBool,
}

impl CallbackSink {
    fn new(callback: Arc<dyn NativeCallback>, canceller: Arc<dyn CancelTarget>) -> Arc<Self> {
        Arc::new(Self {
            callback,
            canceller,
            state: Mutex::new(CallbackState {
                run_id: None,
                cancel_pending: false,
            }),
            callback_failed: AtomicBool::new(false),
            terminal_delivered: AtomicBool::new(false),
        })
    }

    fn bind(&self, run_id: RunId) {
        let cancel = match self.state.lock() {
            Ok(mut state) => {
                state.run_id = Some(run_id);
                state.cancel_pending
            }
            Err(_) => true,
        };
        if cancel {
            self.canceller.cancel(run_id);
        }
    }

    fn callback_failed(&self) {
        if self.callback_failed.swap(true, Ordering::AcqRel) {
            return;
        }
        let run_id = match self.state.lock() {
            Ok(mut state) => match state.run_id {
                Some(run_id) => Some(run_id),
                None => {
                    state.cancel_pending = true;
                    None
                }
            },
            Err(_) => None,
        };
        if let Some(run_id) = run_id {
            self.canceller.cancel(run_id);
        }
    }
}

impl PhaseSink for CallbackSink {
    fn emit(&self, event: SessionEvent) {
        let result = match event {
            SessionEvent::Phase(phase) => self.callback.phase(phase),
            SessionEvent::Terminal(outcome) => {
                if self.terminal_delivered.swap(true, Ordering::AcqRel) {
                    return;
                }
                match outcome {
                    RunOutcome::Complete(receipt) => self.callback.complete(&receipt),
                    RunOutcome::Failed(error) => {
                        self.callback.error(error.category(), &error.to_string())
                    }
                }
            }
        };
        if result.is_err() {
            self.callback_failed();
        }
    }
}

fn contain<T>(operation: impl FnOnce() -> Result<T, ValidatorError>) -> Result<T, ValidatorError> {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or_else(|_| {
        Err(ValidatorError::new(
            ValidatorErrorCategory::Internal,
            "validator JNI boundary failed",
        ))
    })
}

fn decode_utf16(units: &[u16]) -> Result<String, ValidatorError> {
    String::from_utf16(units).map_err(|_| {
        ValidatorError::new(
            ValidatorErrorCategory::Configuration,
            "validator configuration string is invalid",
        )
    })
}

fn decode_java_string(env: &mut Env<'_>, value: &JString<'_>) -> Result<String, ()> {
    let array = env
        .call_method(
            <JString<'_> as AsRef<JObject<'_>>>::as_ref(value),
            jni_str!("toCharArray"),
            jni_sig!("()[C"),
            &[],
        )
        .and_then(|value| value.l())
        .and_then(|value| JCharArray::cast_local(env, value))
        .map_err(|_| ())?;
    let mut units = vec![0; array.len(env).map_err(|_| ())?];
    array.get_region(env, 0, &mut units).map_err(|_| ())?;
    decode_utf16(&units).map_err(|_| ())
}

struct JavaCallback {
    vm: JavaVM,
    callback: Global<JObject<'static>>,
}

impl JavaCallback {
    fn call_one(&self, method: &'static jni::strings::JNIStr, value: &str) -> Result<(), ()> {
        self.vm
            .attach_current_thread(|env| -> jni::errors::Result<()> {
                let value = JString::from_str(env, value)?;
                env.call_method(
                    self.callback.as_obj(),
                    method,
                    jni_sig!("(Ljava/lang/String;)V"),
                    &[JValue::Object(value.as_ref())],
                )?;
                Ok(())
            })
            .map_err(|_| ())
    }

    fn call_two(
        &self,
        method: &'static jni::strings::JNIStr,
        first: &str,
        second: &str,
    ) -> Result<(), ()> {
        self.vm
            .attach_current_thread(|env| -> jni::errors::Result<()> {
                let first = JString::from_str(env, first)?;
                let second = JString::from_str(env, second)?;
                env.call_method(
                    self.callback.as_obj(),
                    method,
                    jni_sig!("(Ljava/lang/String;Ljava/lang/String;)V"),
                    &[
                        JValue::Object(first.as_ref()),
                        JValue::Object(second.as_ref()),
                    ],
                )?;
                Ok(())
            })
            .map_err(|_| ())
    }
}

impl NativeCallback for JavaCallback {
    fn phase(&self, phase: ValidatorPhase) -> Result<(), ()> {
        self.call_one(jni_str!("onPhase"), phase.as_str())
    }

    fn complete(&self, receipt: &ValidationReceipt) -> Result<(), ()> {
        let receipt = serde_json::to_string(receipt).map_err(|_| ())?;
        self.call_one(jni_str!("onComplete"), &receipt)
    }

    fn error(&self, category: ValidatorErrorCategory, message: &str) -> Result<(), ()> {
        self.call_two(jni_str!("onError"), category.as_str(), message)
    }
}

fn native_start(
    env: &mut Env<'_>,
    config_json: &JString<'_>,
    transferred_fd: jint,
    callback: &JObject<'_>,
) -> jni::errors::Result<jlong> {
    // SAFETY: Kotlin transfers ownership with ParcelFileDescriptor.detachFd and must not close it.
    // Adopt before any fallible JNI setup so every return path either moves or drops this OwnedFd.
    let descriptor = if transferred_fd >= 0 {
        Some(unsafe { OwnedFd::from_raw_fd(transferred_fd) })
    } else {
        None
    };
    let vm = env.get_java_vm()?;
    let callback = env.new_global_ref(callback)?;
    let callback: Arc<dyn NativeCallback> = Arc::new(JavaCallback { vm, callback });
    let Some(descriptor) = descriptor else {
        let _ = callback.error(
            ValidatorErrorCategory::Configuration,
            "validator contact descriptor is invalid",
        );
        return Ok(0);
    };
    let config_json = match decode_java_string(env, config_json) {
        Ok(value) => value,
        _ => {
            let _ = callback.error(
                ValidatorErrorCategory::Configuration,
                "validator configuration string is invalid",
            );
            return Ok(0);
        }
    };
    let config = match ValidatorConfig::from_json(&config_json) {
        Ok(config) => config,
        Err(error) => {
            let _ = callback.error(error.category(), &error.to_string());
            return Ok(0);
        }
    };

    let registry = Arc::new(RunRegistry::global().clone());
    let sink = CallbackSink::new(callback.clone(), registry.clone());
    match contain(|| registry.start(config, descriptor, sink.clone())) {
        Ok(run_id) => {
            sink.bind(run_id);
            Ok(run_id.into_raw() as jlong)
        }
        Err(error) => {
            let _ = callback.error(error.category(), &error.to_string());
            Ok(0)
        }
    }
}

struct ActivePreparation {
    id: u64,
    control: Arc<PreparationControl>,
}

#[derive(Default)]
struct PreparationRegistryState {
    active: Option<ActivePreparation>,
    cancelled_through: u64,
}

struct PreparationRegistry {
    state: Mutex<PreparationRegistryState>,
}

impl PreparationRegistry {
    fn new() -> Self {
        Self {
            state: Mutex::new(PreparationRegistryState::default()),
        }
    }

    fn global() -> &'static Self {
        static REGISTRY: OnceLock<PreparationRegistry> = OnceLock::new();
        REGISTRY.get_or_init(Self::new)
    }

    fn begin(&self, id: u64) -> Result<Arc<PreparationControl>, ValidatorError> {
        if id == 0 {
            return Err(ValidatorError::new(
                ValidatorErrorCategory::Configuration,
                "validator preparation identifier is invalid",
            ));
        }
        let mut state = self.state.lock().map_err(|_| {
            ValidatorError::new(
                ValidatorErrorCategory::Internal,
                "validator preparation registry is unavailable",
            )
        })?;
        if id <= state.cancelled_through {
            return Err(ValidatorError::new(
                ValidatorErrorCategory::Unavailable,
                "validator local Event preparation was cancelled",
            ));
        }
        if state.active.is_some() {
            return Err(ValidatorError::new(
                ValidatorErrorCategory::Unavailable,
                "validator preparation is already active",
            ));
        }
        let control = Arc::new(PreparationControl::new());
        state.active = Some(ActivePreparation {
            id,
            control: control.clone(),
        });
        Ok(control)
    }

    fn finish(&self, id: u64) {
        if let Ok(mut state) = self.state.lock()
            && state.active.as_ref().is_some_and(|active| active.id == id)
        {
            state.active.take();
        }
    }

    fn cancel(&self, id: u64) {
        let control = self.state.lock().ok().and_then(|mut state| {
            state.cancelled_through = state.cancelled_through.max(id);
            state
                .active
                .as_ref()
                .filter(|active| active.id == id)
                .map(|active| active.control.clone())
        });
        if let Some(control) = control {
            control.cancel();
        }
    }
}

fn prepare_config(
    config: &ValidatorConfig,
    control: &PreparationControl,
) -> Result<(), ValidatorError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| {
            ValidatorError::new(
                ValidatorErrorCategory::Internal,
                "validator runtime failed to start",
            )
        })?;
    runtime
        .block_on(prepare_local_event_cancellable(config, Some(control)))
        .map(|_| ())
}

fn run_preparation_worker<T>(
    operation: impl FnOnce() -> Result<T, ValidatorError> + Send + 'static,
) -> Result<T, ValidatorError>
where
    T: Send + 'static,
{
    fn worker_error() -> ValidatorError {
        ValidatorError::new(
            ValidatorErrorCategory::Internal,
            "validator local Event preparation worker failed",
        )
    }

    let worker = thread::Builder::new()
        .name(PREPARATION_THREAD_NAME.to_owned())
        .stack_size(PREPARATION_STACK_BYTES)
        .spawn(move || contain(operation))
        .map_err(|_| worker_error())?;
    worker.join().unwrap_or_else(|_| Err(worker_error()))
}

fn native_prepare(
    env: &mut Env<'_>,
    config_json: &JString<'_>,
    preparation_id: jlong,
    callback: &JObject<'_>,
) -> jni::errors::Result<jboolean> {
    let vm = env.get_java_vm()?;
    let callback = env.new_global_ref(callback)?;
    let callback: Arc<dyn NativeCallback> = Arc::new(JavaCallback { vm, callback });
    let config_json = match decode_java_string(env, config_json) {
        Ok(value) => value,
        Err(()) => {
            let _ = callback.error(
                ValidatorErrorCategory::Configuration,
                "validator configuration string is invalid",
            );
            return Ok(false);
        }
    };
    let config = match ValidatorConfig::from_json(&config_json) {
        Ok(config) => config,
        Err(error) => {
            let _ = callback.error(error.category(), &error.to_string());
            return Ok(false);
        }
    };
    let preparation_id = match u64::try_from(preparation_id) {
        Ok(id) if id != 0 => id,
        _ => {
            let _ = callback.error(
                ValidatorErrorCategory::Configuration,
                "validator preparation identifier is invalid",
            );
            return Ok(false);
        }
    };
    let registry = PreparationRegistry::global();
    let control = match contain(|| registry.begin(preparation_id)) {
        Ok(control) => control,
        Err(error) => {
            let _ = callback.error(error.category(), &error.to_string());
            return Ok(false);
        }
    };
    let result = run_preparation_worker(move || prepare_config(&config, &control));
    registry.finish(preparation_id);
    match result {
        Ok(()) => Ok(true),
        Err(error) => {
            let _ = callback.error(error.category(), &error.to_string());
            Ok(false)
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_defenseunicorns_aster_btlering1_NativeValidator_nativePrepare<
    'caller,
>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    config_json: JString<'caller>,
    preparation_id: jlong,
    callback: JObject<'caller>,
) -> jboolean {
    env.with_env(|env| native_prepare(env, &config_json, preparation_id, &callback))
        .resolve::<jni::errors::LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_defenseunicorns_aster_btlering1_NativeValidator_nativeCancelPrepare<
    'caller,
>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    preparation_id: jlong,
) {
    env.with_env(|_| {
        if let Ok(preparation_id) = u64::try_from(preparation_id)
            && preparation_id != 0
        {
            PreparationRegistry::global().cancel(preparation_id);
        }
        Ok::<_, jni::errors::Error>(())
    })
    .resolve::<jni::errors::LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_defenseunicorns_aster_btlering1_NativeValidator_nativeStart<
    'caller,
>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    config_json: JString<'caller>,
    transferred_fd: jint,
    callback: JObject<'caller>,
) -> jlong {
    env.with_env(|env| {
        Ok::<_, jni::errors::Error>(
            native_start(env, &config_json, transferred_fd, &callback).unwrap_or_default(),
        )
    })
    .resolve::<jni::errors::LogErrorAndDefault>()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_defenseunicorns_aster_btlering1_NativeValidator_nativeCancel<
    'caller,
>(
    mut env: EnvUnowned<'caller>,
    _class: JClass<'caller>,
    run_id: jlong,
) {
    env.with_env(|_| {
        if let Ok(run_id) = u64::try_from(run_id)
            && run_id != 0
        {
            let _ = contain(|| RunRegistry::global().cancel(RunId::from_raw(run_id)));
        }
        Ok::<_, jni::errors::Error>(())
    })
    .resolve::<jni::errors::LogErrorAndDefault>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        RunId, RunOutcome, SessionEvent, ValidationReceipt, ValidatorError, ValidatorErrorCategory,
        ValidatorPhase,
    };
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[test]
    fn preparation_worker_has_bounded_node_stack() {
        let observed = run_preparation_worker(|| {
            assert_eq!(std::thread::current().name(), Some(PREPARATION_THREAD_NAME));
            let mut stack_demand = [0_u8; 2 * 1024 * 1024];
            for page in stack_demand.chunks_mut(4096) {
                page[0] = 0x5a;
            }
            Ok(stack_demand[0])
        })
        .expect("preparation worker");

        assert_eq!(observed, 0x5a);
        assert_eq!(PREPARATION_STACK_BYTES, 8 * 1024 * 1024);
    }

    #[derive(Default)]
    struct RecordingCallback {
        calls: Mutex<Vec<String>>,
        fail: bool,
    }

    impl NativeCallback for RecordingCallback {
        fn phase(&self, phase: ValidatorPhase) -> Result<(), ()> {
            self.calls
                .lock()
                .expect("callback calls")
                .push(format!("phase:{phase:?}"));
            if self.fail { Err(()) } else { Ok(()) }
        }

        fn complete(&self, _receipt: &ValidationReceipt) -> Result<(), ()> {
            self.calls
                .lock()
                .expect("callback calls")
                .push("complete".to_owned());
            if self.fail { Err(()) } else { Ok(()) }
        }

        fn error(&self, category: ValidatorErrorCategory, _message: &str) -> Result<(), ()> {
            self.calls
                .lock()
                .expect("callback calls")
                .push(format!("error:{category:?}"));
            if self.fail { Err(()) } else { Ok(()) }
        }
    }

    #[derive(Default)]
    struct RecordingCanceller {
        calls: AtomicUsize,
    }

    impl CancelTarget for RecordingCanceller {
        fn cancel(&self, _id: RunId) {
            self.calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn panic_is_converted_to_internal_error() {
        let error = contain(|| -> Result<(), ValidatorError> { panic!("secret panic") })
            .expect_err("panic contained");

        assert_eq!(error.category(), ValidatorErrorCategory::Internal);
        assert_eq!(error.to_string(), "validator JNI boundary failed");
    }

    #[test]
    fn invalid_utf16_and_json_do_not_start() {
        let utf16 = decode_utf16(&[0xd800]).expect_err("unpaired surrogate rejected");
        assert_eq!(utf16.category(), ValidatorErrorCategory::Configuration);
        assert_eq!(
            decode_utf16(&[0xfffd]).expect("valid replacement char"),
            "\u{fffd}"
        );

        let json = decode_utf16(&[u16::from(b'{')]).expect("valid UTF-16");
        let error = crate::ValidatorConfig::from_json(&json).expect_err("invalid JSON rejected");
        assert_eq!(error.category(), ValidatorErrorCategory::Configuration);
    }

    #[test]
    fn callback_exception_cancels_and_releases_run() {
        let callback = Arc::new(RecordingCallback {
            calls: Mutex::new(Vec::new()),
            fail: true,
        });
        let canceller = Arc::new(RecordingCanceller::default());
        let sink = CallbackSink::new(callback, canceller.clone());
        sink.bind(RunId::from_raw(41));

        sink.emit(SessionEvent::Phase(ValidatorPhase::CarrierConnected));
        sink.emit(SessionEvent::Phase(ValidatorPhase::Authenticating));

        assert_eq!(canceller.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn terminal_callback_is_delivered_once() {
        let callback = Arc::new(RecordingCallback::default());
        let sink = CallbackSink::new(callback.clone(), Arc::new(RecordingCanceller::default()));
        sink.bind(RunId::from_raw(7));
        let failure = RunOutcome::Failed(ValidatorError::new(
            ValidatorErrorCategory::Timeout,
            "validator contact timed out",
        ));

        sink.emit(SessionEvent::Terminal(failure.clone()));
        sink.emit(SessionEvent::Terminal(failure));

        assert_eq!(
            callback.calls.lock().expect("callback calls").as_slice(),
            ["error:Timeout"]
        );
    }

    #[test]
    fn preparation_registry_carries_cancellation_across_registration() {
        let registry = PreparationRegistry::new();
        let control = registry.begin(41).expect("start preparation");
        assert!(registry.begin(42).is_err());

        registry.cancel(42);
        assert!(!control.is_cancelled());
        registry.cancel(41);
        assert!(control.is_cancelled());

        registry.finish(41);
        let Err(error) = registry.begin(42) else {
            panic!("queued preparation was cancelled");
        };
        assert_eq!(error.category(), ValidatorErrorCategory::Unavailable);

        let next = registry.begin(43).expect("newer preparation may start");
        assert!(!next.is_cancelled());
        registry.finish(43);
    }
}
