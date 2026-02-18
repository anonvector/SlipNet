//! Android JNI bindings for the slipstream client.
//!
//! This module provides the JNI interface for the Android VPN app, including:
//! - Client lifecycle management (start/stop)
//! - State flags (running, listener ready, QUIC ready)
//! - Socket protection via VpnService.protect()

use crate::error::ClientError;
use crate::runtime::run_client;
use jni::objects::{JBooleanArray, JClass, JIntArray, JObject, JObjectArray, JString, JValue};
use jni::sys::{jboolean, jbooleanArray, jint, jintArray, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use once_cell::sync::OnceCell;
use slipstream_core::HostPort;
use slipstream_ffi::{ClientConfig, ResolverMode, ResolverSpec};
use std::os::unix::io::RawFd;
use std::panic;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};
use tokio::runtime::Builder;
use tracing::{debug, error, info, warn};

// ============================================================================
// Global State
// ============================================================================

/// Flag indicating whether the client is running.
static IS_RUNNING: AtomicBool = AtomicBool::new(false);

/// Flag indicating whether the TCP listener is ready.
static IS_LISTENER_READY: AtomicBool = AtomicBool::new(false);

/// Flag indicating whether the QUIC connection is established and ready.
static IS_QUIC_READY: AtomicBool = AtomicBool::new(false);

/// Flag to signal the client thread to shut down.
static SHOULD_SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// Flag indicating the client thread has finished.
static IS_THREAD_DONE: AtomicBool = AtomicBool::new(true);

/// Count of consecutive connection failures (connections that never became ready).
static CONSECUTIVE_FAILURES: AtomicI32 = AtomicI32::new(0);

/// Maximum consecutive failures before giving up.
const MAX_CONSECUTIVE_FAILURES: i32 = 5;

/// Handle to the client thread.
static CLIENT_THREAD: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

/// Global JVM reference for callbacks.
static JAVA_VM: OnceCell<jni::JavaVM> = OnceCell::new();

/// Cached global reference to SlipstreamBridge class.
/// This is needed because native threads can't find app classes via the system class loader.
static BRIDGE_CLASS: OnceCell<jni::objects::GlobalRef> = OnceCell::new();

// ============================================================================
// Public API for Rust code
// ============================================================================

/// Check if the client should shut down.
pub fn should_shutdown() -> bool {
    SHOULD_SHUTDOWN.load(Ordering::SeqCst)
}

/// Signal that the TCP listener is ready.
pub fn signal_listener_ready() {
    IS_LISTENER_READY.store(true, Ordering::SeqCst);
    info!("TCP listener is ready");
}

/// Signal that the QUIC connection is ready.
pub fn signal_quic_ready() {
    IS_QUIC_READY.store(true, Ordering::SeqCst);
    CONSECUTIVE_FAILURES.store(0, Ordering::SeqCst);
    info!("QUIC connection is ready");
}

/// Reset the QUIC ready flag (called on reconnect).
pub fn reset_quic_ready() {
    IS_QUIC_READY.store(false, Ordering::SeqCst);
    debug!("QUIC ready flag reset for reconnection");
}

/// Record a connection failure (connection that never became ready).
pub fn record_connection_failure() {
    let failures = CONSECUTIVE_FAILURES.fetch_add(1, Ordering::SeqCst) + 1;
    warn!("Connection failure recorded, total: {}", failures);
}

/// Check if we've exceeded the maximum consecutive failures.
pub fn exceeded_max_failures() -> bool {
    CONSECUTIVE_FAILURES.load(Ordering::SeqCst) >= MAX_CONSECUTIVE_FAILURES
}

/// Protect a socket file descriptor via VpnService.protect().
/// This MUST be called for the UDP socket used for DNS queries BEFORE sending any data.
/// Returns true if protection succeeded, false otherwise.
pub fn protect_socket(fd: RawFd) -> bool {
    let jvm = match JAVA_VM.get() {
        Some(vm) => vm,
        None => {
            error!("JavaVM not initialized, cannot protect socket");
            return false;
        }
    };

    let class_ref = match BRIDGE_CLASS.get() {
        Some(c) => c,
        None => {
            error!("SlipstreamBridge class not cached, cannot protect socket");
            return false;
        }
    };

    let mut env = match jvm.attach_current_thread() {
        Ok(env) => env,
        Err(e) => {
            error!("Failed to attach to JVM: {:?}", e);
            return false;
        }
    };

    // Call SlipstreamBridge.protectSocket(fd) using cached class reference
    // Safety: GlobalRef holds a valid JNI reference, converting to JClass is safe
    let class = unsafe { JClass::from_raw(class_ref.as_raw()) };
    let result = env.call_static_method(
        class,
        "protectSocket",
        "(I)Z",
        &[JValue::Int(fd)],
    );

    match result {
        Ok(val) => {
            let protected = val.z().unwrap_or(false);
            if protected {
                debug!("Socket fd={} protected successfully", fd);
            } else {
                warn!("Socket fd={} protection returned false", fd);
            }
            protected
        }
        Err(e) => {
            error!("Failed to call protectSocket: {:?}", e);
            // Clear any pending exception
            let _ = env.exception_clear();
            false
        }
    }
}

// ============================================================================
// JNI Functions
// ============================================================================

/// Initialize Android logging.
fn init_android_logging() {
    #[cfg(target_os = "android")]
    {
        use android_logger::Config;
        use log::LevelFilter;

        let _ = android_logger::init_once(
            Config::default()
                .with_max_level(LevelFilter::Debug)
                .with_tag("SlipstreamRust"),
        );
    }

    // Also initialize tracing for the slipstream code
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .try_init();
}

/// JNI_OnLoad - Called when the library is loaded.
#[no_mangle]
pub extern "system" fn JNI_OnLoad(vm: jni::JavaVM, _: *mut std::ffi::c_void) -> jint {
    init_android_logging();
    info!("slipstream library loaded");

    if JAVA_VM.set(vm).is_err() {
        error!("Failed to store JavaVM reference");
        return jni::sys::JNI_ERR;
    }

    jni::sys::JNI_VERSION_1_6
}

/// Start the slipstream client.
///
/// # Arguments
/// - domain: The domain for DNS tunneling
/// - resolverHosts: Array of resolver hostnames/IPs
/// - resolverPorts: Array of resolver ports
/// - resolverAuthoritative: Array of booleans indicating authoritative mode
/// - listenPort: TCP port to listen on
/// - listenHost: TCP host to bind to
/// - congestionControl: Congestion control algorithm ("bbr" or "dcubic")
/// - keepAliveInterval: Keep-alive interval in ms
/// - gsoEnabled: Enable Generic Segmentation Offload
/// - debugPoll: Enable debug logging for DNS polling
/// - debugStreams: Enable debug logging for streams
///
/// # Returns
/// - 0: Success
/// - -1: Invalid domain
/// - -2: Invalid resolver configuration
/// - -10: Failed to spawn client thread
/// - -11: Failed to listen on port
/// - -12: Exceeded max connection failures
#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeStartSlipstreamClient<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    domain: JString<'local>,
    resolver_hosts: JObjectArray<'local>,
    resolver_ports: jintArray,
    resolver_authoritative: jbooleanArray,
    listen_port: jint,
    listen_host: JString<'local>,
    congestion_control: JString<'local>,
    keep_alive_interval: jint,
    gso_enabled: jboolean,
    debug_poll: jboolean,
    debug_streams: jboolean,
    idle_poll_interval: jint,
) -> jint {
    // Catch panics to prevent crashes
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        start_client_impl(
            &mut env,
            domain,
            resolver_hosts,
            resolver_ports,
            resolver_authoritative,
            listen_port,
            listen_host,
            congestion_control,
            keep_alive_interval,
            gso_enabled,
            debug_poll,
            debug_streams,
            idle_poll_interval,
        )
    }));

    match result {
        Ok(code) => code,
        Err(e) => {
            error!("Panic in nativeStartSlipstreamClient: {:?}", e);
            IS_RUNNING.store(false, Ordering::SeqCst);
            -100
        }
    }
}

fn start_client_impl<'local>(
    env: &mut JNIEnv<'local>,
    domain: JString<'local>,
    resolver_hosts: JObjectArray<'local>,
    resolver_ports: jintArray,
    resolver_authoritative: jbooleanArray,
    listen_port: jint,
    listen_host: JString<'local>,
    congestion_control: JString<'local>,
    keep_alive_interval: jint,
    gso_enabled: jboolean,
    debug_poll: jboolean,
    debug_streams: jboolean,
    idle_poll_interval: jint,
) -> jint {
    info!("nativeStartSlipstreamClient called");

    // Check if already running
    if IS_RUNNING.load(Ordering::SeqCst) {
        warn!("Client already running");
        return 0;
    }

    // Cache the SlipstreamBridge class for callbacks from native threads.
    // This must be done on the Java thread that has access to the app class loader.
    if BRIDGE_CLASS.get().is_none() {
        let class_name = "app/slipnet/tunnel/SlipstreamBridge";
        match env.find_class(class_name) {
            Ok(class) => {
                match env.new_global_ref(class) {
                    Ok(global_ref) => {
                        let _ = BRIDGE_CLASS.set(global_ref);
                        info!("Cached SlipstreamBridge class for callbacks");
                    }
                    Err(e) => {
                        error!("Failed to create global ref for SlipstreamBridge: {:?}", e);
                        return -3;
                    }
                }
            }
            Err(e) => {
                error!("Failed to find SlipstreamBridge class: {:?}", e);
                return -3;
            }
        }
    }

    // Wait for any abandoned thread to finish. After nativeStop abandons a thread,
    // SHOULD_SHUTDOWN stays true so the thread can see it and exit. Wait here for
    // that to happen before resetting the flag for the new thread.
    if !IS_THREAD_DONE.load(Ordering::SeqCst) {
        info!("Waiting for previous client thread to finish...");
        for _ in 0..30 {
            if IS_THREAD_DONE.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(100));
        }
        if !IS_THREAD_DONE.load(Ordering::SeqCst) {
            warn!("Previous client thread still running, proceeding anyway");
        }
    }

    // Reset state
    SHOULD_SHUTDOWN.store(false, Ordering::SeqCst);
    IS_LISTENER_READY.store(false, Ordering::SeqCst);
    IS_QUIC_READY.store(false, Ordering::SeqCst);
    IS_THREAD_DONE.store(false, Ordering::SeqCst);
    CONSECUTIVE_FAILURES.store(0, Ordering::SeqCst);

    // Extract domain
    let domain_str: String = match env.get_string(&domain) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get domain string: {:?}", e);
            return -1;
        }
    };

    if domain_str.is_empty() {
        error!("Domain is empty");
        return -1;
    }

    // Extract listen host
    let listen_host_str: String = match env.get_string(&listen_host) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get listen host string: {:?}", e);
            return -2;
        }
    };

    // Extract congestion control
    let cc_str: String = match env.get_string(&congestion_control) {
        Ok(s) => s.into(),
        Err(e) => {
            error!("Failed to get congestion control string: {:?}", e);
            return -2;
        }
    };
    let cc_option = if cc_str.is_empty() { None } else { Some(cc_str) };

    // Extract resolver configuration
    let resolver_count = match env.get_array_length(&resolver_hosts) {
        Ok(len) => len as usize,
        Err(e) => {
            error!("Failed to get resolver hosts length: {:?}", e);
            return -2;
        }
    };

    if resolver_count == 0 {
        error!("No resolvers provided");
        return -2;
    }

    // Wrap raw arrays in safe JNI types
    let resolver_ports_arr = unsafe { JIntArray::from_raw(resolver_ports) };
    let resolver_auth_arr = unsafe { JBooleanArray::from_raw(resolver_authoritative) };

    // Get ports array using get_array_region which is more portable
    let mut ports: Vec<i32> = vec![0; resolver_count];
    if let Err(e) = env.get_int_array_region(&resolver_ports_arr, 0, &mut ports) {
        error!("Failed to get resolver ports: {:?}", e);
        return -2;
    }

    // Get authoritative flags using get_array_region
    let mut auth_flags: Vec<u8> = vec![0; resolver_count];
    if let Err(e) = env.get_boolean_array_region(&resolver_auth_arr, 0, &mut auth_flags) {
        error!("Failed to get authoritative flags: {:?}", e);
        return -2;
    }

    // Build resolver specs
    let mut resolvers: Vec<ResolverSpec> = Vec::with_capacity(resolver_count);
    for i in 0..resolver_count {
        // Get host string
        let host_obj: JObject = match env.get_object_array_element(&resolver_hosts, i as i32) {
            Ok(obj) => obj,
            Err(e) => {
                error!("Failed to get resolver host at index {}: {:?}", i, e);
                return -2;
            }
        };
        let host_jstr = JString::from(host_obj);
        let host: String = match env.get_string(&host_jstr) {
            Ok(s) => s.into(),
            Err(e) => {
                error!("Failed to convert resolver host at index {}: {:?}", i, e);
                return -2;
            }
        };

        let port = ports[i] as u16;
        let authoritative = auth_flags[i] != 0;

        let mode = if authoritative {
            ResolverMode::Authoritative
        } else {
            ResolverMode::Recursive
        };

        // Use V4 as default address family - DNS over UDP typically uses IPv4
        resolvers.push(ResolverSpec {
            resolver: HostPort {
                host,
                port,
                family: slipstream_core::AddressFamily::V4,
            },
            mode,
        });
    }

    info!(
        "Starting client: domain={}, resolvers={}, port={}, host={}",
        domain_str, resolver_count, listen_port, listen_host_str
    );

    // Mark as running
    IS_RUNNING.store(true, Ordering::SeqCst);

    // Spawn client thread
    let listen_port_u16 = listen_port as u16;
    let keep_alive = keep_alive_interval as usize;
    let gso = gso_enabled != JNI_FALSE;
    let dbg_poll = debug_poll != JNI_FALSE;
    let dbg_streams = debug_streams != JNI_FALSE;
    let idle_poll_ms = idle_poll_interval.max(0) as u64;

    let handle = thread::Builder::new()
        .name("slipstream-client".to_string())
        .spawn(move || {
            run_client_thread(
                domain_str,
                resolvers,
                listen_port_u16,
                listen_host_str,
                cc_option,
                keep_alive,
                gso,
                dbg_poll,
                dbg_streams,
                idle_poll_ms,
            );
        });

    match handle {
        Ok(h) => {
            let mut guard = CLIENT_THREAD.lock().unwrap();
            *guard = Some(h);
            info!("Client thread spawned successfully");

            // Wait for listener to be ready (up to 5 seconds)
            for _ in 0..50 {
                if IS_LISTENER_READY.load(Ordering::SeqCst) {
                    info!("Listener confirmed ready");
                    return 0;
                }
                if !IS_RUNNING.load(Ordering::SeqCst) {
                    error!("Client stopped before listener ready");
                    return -11;
                }
                thread::sleep(std::time::Duration::from_millis(100));
            }

            if IS_LISTENER_READY.load(Ordering::SeqCst) {
                0
            } else {
                error!("Timeout waiting for listener");
                // Don't stop - the listener might still come up
                0
            }
        }
        Err(e) => {
            error!("Failed to spawn client thread: {:?}", e);
            IS_RUNNING.store(false, Ordering::SeqCst);
            -10
        }
    }
}

fn run_client_thread(
    domain: String,
    resolvers: Vec<ResolverSpec>,
    listen_port: u16,
    listen_host: String,
    congestion_control: Option<String>,
    keep_alive_interval: usize,
    gso: bool,
    debug_poll: bool,
    debug_streams: bool,
    idle_poll_interval_ms: u64,
) {
    info!("Client thread started");

    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let config = ClientConfig {
            tcp_listen_host: &listen_host,
            tcp_listen_port: listen_port,
            resolvers: &resolvers,
            domain: &domain,
            cert: None, // TODO: Support certificate pinning from Android
            congestion_control: congestion_control.as_deref(),
            gso,
            keep_alive_interval,
            debug_poll,
            debug_streams,
            idle_poll_interval_ms,
        };

        // Build tokio runtime
        let runtime = match Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                error!("Failed to build tokio runtime: {:?}", e);
                return;
            }
        };

        // Run the client
        match runtime.block_on(run_client_with_protection(&config)) {
            Ok(code) => {
                info!("Client exited with code: {}", code);
            }
            Err(e) => {
                error!("Client error: {:?}", e);
            }
        }
    }));

    if let Err(e) = result {
        error!("Panic in client thread: {:?}", e);
    }

    // Cleanup
    IS_RUNNING.store(false, Ordering::SeqCst);
    IS_LISTENER_READY.store(false, Ordering::SeqCst);
    IS_QUIC_READY.store(false, Ordering::SeqCst);
    IS_THREAD_DONE.store(true, Ordering::SeqCst);

    info!("Client thread finished");
}

/// Run the client with socket protection.
/// This wraps run_client and ensures the UDP socket is protected.
async fn run_client_with_protection(config: &ClientConfig<'_>) -> Result<i32, ClientError> {
    // The socket protection happens inside the modified bind_udp_socket function
    // which calls protect_socket() after creating the socket.
    run_client(config).await
}

/// Stop the slipstream client.
#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeStopSlipstreamClient(
    _env: JNIEnv,
    _class: JClass,
) {
    info!("nativeStopSlipstreamClient called");

    // Signal shutdown
    SHOULD_SHUTDOWN.store(true, Ordering::SeqCst);

    // Give the client thread time to exit gracefully
    let mut waited = 0;
    while !IS_THREAD_DONE.load(Ordering::SeqCst) && waited < 3000 {
        thread::sleep(std::time::Duration::from_millis(100));
        waited += 100;
    }

    if !IS_THREAD_DONE.load(Ordering::SeqCst) {
        warn!("Client thread did not exit within timeout, abandoning");
        // Abandon the thread handle to avoid blocking
        let mut guard = CLIENT_THREAD.lock().unwrap();
        if let Some(handle) = guard.take() {
            std::mem::forget(handle);
        }
        // Leave SHOULD_SHUTDOWN=true so the abandoned thread sees it and exits,
        // releasing the TCP listener port. The next nativeStart resets it.
    } else {
        // Join the thread if it exited
        let mut guard = CLIENT_THREAD.lock().unwrap();
        if let Some(handle) = guard.take() {
            let _ = handle.join();
        }
        SHOULD_SHUTDOWN.store(false, Ordering::SeqCst);
    }

    // Reset state
    IS_RUNNING.store(false, Ordering::SeqCst);
    IS_LISTENER_READY.store(false, Ordering::SeqCst);
    IS_QUIC_READY.store(false, Ordering::SeqCst);

    info!("Client stopped");
}

/// Check if the client is running.
#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeIsClientRunning(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if IS_RUNNING.load(Ordering::SeqCst) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Check if the QUIC connection is ready.
#[no_mangle]
pub extern "system" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeIsQuicReady(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if IS_QUIC_READY.load(Ordering::SeqCst) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_flags() {
        // Initial state
        assert!(!IS_RUNNING.load(Ordering::SeqCst));
        assert!(!IS_LISTENER_READY.load(Ordering::SeqCst));
        assert!(!IS_QUIC_READY.load(Ordering::SeqCst));

        // Set flags
        IS_RUNNING.store(true, Ordering::SeqCst);
        signal_listener_ready();
        signal_quic_ready();

        assert!(IS_RUNNING.load(Ordering::SeqCst));
        assert!(IS_LISTENER_READY.load(Ordering::SeqCst));
        assert!(IS_QUIC_READY.load(Ordering::SeqCst));

        // Reset
        reset_quic_ready();
        assert!(!IS_QUIC_READY.load(Ordering::SeqCst));

        // Cleanup
        IS_RUNNING.store(false, Ordering::SeqCst);
        IS_LISTENER_READY.store(false, Ordering::SeqCst);
    }

    #[test]
    fn test_failure_tracking() {
        CONSECUTIVE_FAILURES.store(0, Ordering::SeqCst);

        assert!(!exceeded_max_failures());

        for _ in 0..MAX_CONSECUTIVE_FAILURES {
            record_connection_failure();
        }

        assert!(exceeded_max_failures());

        // Reset
        CONSECUTIVE_FAILURES.store(0, Ordering::SeqCst);
    }
}
