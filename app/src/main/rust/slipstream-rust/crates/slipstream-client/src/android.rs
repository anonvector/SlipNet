//! Android JNI bindings for slipstream client.
//!
//! This module provides native functions that can be called from Kotlin/Java
//! to start and stop the slipstream DNS tunnel client.

use jni::objects::{JClass, JIntArray, JObjectArray, JString, ReleaseMode};
use jni::sys::{jboolean, jint, JavaVM, JNI_FALSE, JNI_TRUE, JNI_VERSION_1_6};
use jni::JNIEnv;
use slipstream_core::{parse_host_port_parts, AddressKind};
use slipstream_ffi::{ClientConfig, ResolverMode, ResolverSpec};
use std::os::raw::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock};
use tokio::sync::oneshot;
use tracing::{debug, error, info, warn};

use crate::run_client;

/// Global JavaVM pointer for socket protection from any thread
static JAVA_VM: AtomicPtr<jni::sys::JavaVM> = AtomicPtr::new(std::ptr::null_mut());

/// Global reference to SlipstreamBridge class (cached to avoid classloader issues)
static BRIDGE_CLASS: OnceLock<jni::objects::GlobalRef> = OnceLock::new();

/// JNI_OnLoad is called when the native library is loaded.
/// This ensures the JNI symbols are exported and not stripped by the linker.
#[no_mangle]
pub extern "C" fn JNI_OnLoad(vm: *mut JavaVM, _reserved: *mut c_void) -> jint {
    // Store the JavaVM pointer for later use in socket protection
    JAVA_VM.store(vm, Ordering::SeqCst);

    // Cache the SlipstreamBridge class reference using the app's classloader
    // This must be done here because native threads can't find app classes
    let vm_wrapper = match unsafe { jni::JavaVM::from_raw(vm) } {
        Ok(v) => v,
        Err(_) => return JNI_VERSION_1_6,
    };

    if let Ok(mut env) = vm_wrapper.get_env() {
        if let Ok(class) = env.find_class("app/slipnet/tunnel/SlipstreamBridge") {
            if let Ok(global_ref) = env.new_global_ref(class) {
                let _ = BRIDGE_CLASS.set(global_ref);
                info!("JNI_OnLoad: SlipstreamBridge class cached successfully");
            }
        }
    }

    // Don't drop the JavaVM wrapper - we don't own it
    std::mem::forget(vm_wrapper);

    info!("JNI_OnLoad: JavaVM stored for socket protection");
    JNI_VERSION_1_6
}

/// Global state for the running client
static CLIENT_STATE: OnceLock<Mutex<Option<ClientHandle>>> = OnceLock::new();
static IS_RUNNING: AtomicBool = AtomicBool::new(false);

struct ClientHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

fn get_client_state() -> &'static Mutex<Option<ClientHandle>> {
    CLIENT_STATE.get_or_init(|| Mutex::new(None))
}

/// Initialize Android logging
fn init_android_logging() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::EnvFilter;

    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("info,slipstream=debug"));

        let android_layer = tracing_android::layer("SlipstreamRust").unwrap();

        let _ = tracing_subscriber::registry()
            .with(filter)
            .with(android_layer)
            .try_init();
    });
}

/// Helper to get a Java string as Rust String
fn get_string(env: &mut JNIEnv, obj: &JString) -> Result<String, jni::errors::Error> {
    let jstr = env.get_string(obj)?;
    Ok(jstr.into())
}

/// Protect a socket from the VPN by calling back to Kotlin.
/// This can be called from any thread as it attaches to the JVM if needed.
///
/// Returns true if the socket was successfully protected.
pub fn protect_socket(fd: i32) -> bool {
    let vm_ptr = JAVA_VM.load(Ordering::SeqCst);
    if vm_ptr.is_null() {
        error!("Cannot protect socket: JavaVM not stored");
        return false;
    }

    // Get the cached class reference
    let bridge_class = match BRIDGE_CLASS.get() {
        Some(c) => c,
        None => {
            error!("Cannot protect socket: SlipstreamBridge class not cached");
            return false;
        }
    };

    // SAFETY: We stored a valid JavaVM pointer in JNI_OnLoad
    let vm = match unsafe { jni::JavaVM::from_raw(vm_ptr) } {
        Ok(vm) => vm,
        Err(e) => {
            error!("Failed to create JavaVM from raw pointer: {:?}", e);
            return false;
        }
    };

    // Attach this thread to the JVM as a daemon thread
    // This is safe to call even if already attached
    let mut env = match vm.attach_current_thread_as_daemon() {
        Ok(env) => env,
        Err(e) => {
            error!("Failed to attach thread to JVM: {:?}", e);
            // Don't drop the JavaVM, we don't own it
            std::mem::forget(vm);
            return false;
        }
    };

    // Clear any pending exception first
    if env.exception_check().unwrap_or(false) {
        warn!("Clearing pending Java exception before protectSocket call");
        let _ = env.exception_clear();
    }

    // Use the cached class reference (works from any thread)
    // Convert GlobalRef to JClass - safe because we created it from a JClass in JNI_OnLoad
    let class_obj: &jni::objects::JObject = bridge_class.as_ref();
    // SAFETY: We know this JObject is actually a JClass because we created it from find_class
    let class_ref: jni::objects::JClass = unsafe {
        jni::objects::JClass::from_raw(class_obj.as_raw())
    };
    let result = env.call_static_method(
        class_ref,
        "protectSocket",
        "(I)Z",
        &[jni::objects::JValue::Int(fd)],
    );

    // Check for and log any Java exception
    if env.exception_check().unwrap_or(false) {
        error!("Java exception occurred during protectSocket call:");
        let _ = env.exception_describe();
        let _ = env.exception_clear();
    }

    // Extract the result before dropping env
    let protected = match result {
        Ok(jvalue) => {
            match jvalue.z() {
                Ok(p) => {
                    if p {
                        debug!("Protected socket fd={}", fd);
                    } else {
                        warn!("Failed to protect socket fd={} (VpnService returned false)", fd);
                    }
                    p
                }
                Err(e) => {
                    error!("Failed to convert protectSocket result to boolean: {:?}", e);
                    false
                }
            }
        }
        Err(e) => {
            error!("Failed to call protectSocket: {:?}", e);
            false
        }
    };

    // Don't drop the JavaVM - we don't own it
    drop(env);
    std::mem::forget(vm);

    protected
}

/// Start the slipstream client.
///
/// # Arguments
/// * `domain` - The domain for DNS tunneling
/// * `resolver_hosts` - Array of resolver hostnames (e.g., ["8.8.8.8", "1.1.1.1"])
/// * `resolver_ports` - Array of resolver ports
/// * `resolver_authoritative` - Array of booleans indicating if resolver is authoritative
/// * `listen_port` - TCP port to listen on for SOCKS5 connections
/// * `listen_host` - TCP host to bind to (e.g., "127.0.0.1" or "::")
/// * `congestion_control` - Congestion control algorithm ("bbr" or "dcubic")
/// * `keep_alive_interval` - Keep-alive interval in milliseconds
/// * `gso_enabled` - Whether to enable GSO (Generic Segmentation Offload)
/// * `debug_poll` - Enable debug logging for DNS polling
/// * `debug_streams` - Enable debug logging for streams
///
/// # Returns
/// * 0 on success
/// * -1 on invalid domain
/// * -2 on invalid resolver configuration
/// * -10 on failed to spawn client thread
/// * -11 on failed to listen on port
/// * -100 on other errors
#[no_mangle]
pub unsafe extern "C" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeStartSlipstreamClient(
    mut env: JNIEnv,
    _class: JClass,
    domain: JString,
    resolver_hosts: JObjectArray,
    resolver_ports: jni::sys::jintArray,
    resolver_authoritative: jni::sys::jbooleanArray,
    listen_port: jint,
    listen_host: JString,
    congestion_control: JString,
    keep_alive_interval: jint,
    gso_enabled: jboolean,
    debug_poll: jboolean,
    debug_streams: jboolean,
) -> jint {
    init_android_logging();

    info!("nativeStartSlipstreamClient called");

    // Check if already running
    if IS_RUNNING.load(Ordering::SeqCst) {
        warn!("Client already running");
        return -10;
    }

    // Parse domain
    let domain_str = match get_string(&mut env, &domain) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get domain string: {:?}", e);
            return -1;
        }
    };

    // Parse listen host
    let listen_host_str = match get_string(&mut env, &listen_host) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get listen host string: {:?}", e);
            return -1;
        }
    };

    // Parse congestion control
    let congestion_control_str = match get_string(&mut env, &congestion_control) {
        Ok(s) => {
            if s.is_empty() {
                None
            } else {
                Some(s)
            }
        }
        Err(e) => {
            error!("Failed to get congestion control string: {:?}", e);
            return -7;
        }
    };

    // Parse resolvers
    let resolver_count = match env.get_array_length(&resolver_hosts) {
        Ok(len) => len as usize,
        Err(e) => {
            error!("Failed to get resolver hosts length: {:?}", e);
            return -2;
        }
    };

    // Get ports array
    let ports_array = unsafe { JIntArray::from_raw(resolver_ports) };
    let ports: Vec<i32> = match unsafe { env.get_array_elements(&ports_array, ReleaseMode::NoCopyBack) } {
        Ok(elements) => {
            let slice: &[i32] = unsafe { std::slice::from_raw_parts(elements.as_ptr(), resolver_count) };
            slice.to_vec()
        }
        Err(e) => {
            error!("Failed to get resolver ports: {:?}", e);
            return -3;
        }
    };

    // Get authoritative array - JNI uses u8 for booleans
    let auth_array = unsafe { jni::objects::JBooleanArray::from_raw(resolver_authoritative) };
    let authoritative: Vec<bool> = match unsafe { env.get_array_elements(&auth_array, ReleaseMode::NoCopyBack) } {
        Ok(elements) => {
            let slice: &[u8] = unsafe { std::slice::from_raw_parts(elements.as_ptr(), resolver_count) };
            slice.iter().map(|&b| b != 0).collect()
        }
        Err(e) => {
            error!("Failed to get resolver authoritative flags: {:?}", e);
            return -2;
        }
    };

    // Build resolver specs
    let mut resolvers = Vec::with_capacity(resolver_count);
    for i in 0..resolver_count {
        let host_obj = match env.get_object_array_element(&resolver_hosts, i as i32) {
            Ok(obj) => obj,
            Err(e) => {
                error!("Failed to get resolver host at index {}: {:?}", i, e);
                return -4;
            }
        };

        let host_str = match get_string(&mut env, &JString::from(host_obj)) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to convert resolver host at index {}: {:?}", i, e);
                return -5;
            }
        };

        let port = ports.get(i).copied().unwrap_or(53) as u16;
        let is_authoritative = authoritative.get(i).copied().unwrap_or(false);

        // Parse the host:port
        let host_port = match parse_host_port_parts(&host_str, port, AddressKind::Resolver) {
            Ok(hp) => hp,
            Err(e) => {
                error!("Failed to parse resolver {}:{}: {:?}", host_str, port, e);
                return -6;
            }
        };

        let mode = if is_authoritative {
            ResolverMode::Authoritative
        } else {
            ResolverMode::Recursive
        };

        resolvers.push(ResolverSpec {
            resolver: host_port,
            mode,
        });

        info!(
            "Resolver {}: {}:{} ({})",
            i,
            host_str,
            port,
            if is_authoritative {
                "authoritative"
            } else {
                "recursive"
            }
        );
    }

    if resolvers.is_empty() {
        error!("No resolvers configured");
        return -2;
    }

    let listen_port_u16 = listen_port as u16;
    let keep_alive_ms = keep_alive_interval as usize;
    let gso = gso_enabled != JNI_FALSE;
    let debug_poll_flag = debug_poll != JNI_FALSE;
    let debug_streams_flag = debug_streams != JNI_FALSE;

    info!("Starting slipstream client:");
    info!("  Domain: {}", domain_str);
    info!("  Listen: {}:{}", listen_host_str, listen_port_u16);
    info!("  Resolvers: {}", resolvers.len());
    info!(
        "  Congestion control: {}",
        congestion_control_str.as_deref().unwrap_or("default")
    );
    info!("  Keep-alive: {}ms", keep_alive_ms);
    info!("  GSO: {}", gso);
    info!("  Debug poll: {}", debug_poll_flag);
    info!("  Debug streams: {}", debug_streams_flag);

    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    IS_RUNNING.store(true, Ordering::SeqCst);

    // Spawn the client in a separate thread
    let domain_owned = domain_str.clone();
    let listen_host_owned = listen_host_str.clone();
    let congestion_control_owned = congestion_control_str.clone();
    let resolvers_owned = resolvers.clone();

    let thread_handle = std::thread::spawn(move || {
        let config = ClientConfig {
            tcp_listen_host: &listen_host_owned,
            tcp_listen_port: listen_port_u16,
            resolvers: &resolvers_owned,
            domain: &domain_owned,
            cert: None, // Certificate pinning disabled on Android
            congestion_control: congestion_control_owned.as_deref(),
            gso,
            keep_alive_interval: keep_alive_ms,
            debug_poll: debug_poll_flag,
            debug_streams: debug_streams_flag,
        };

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("Failed to create tokio runtime");

        rt.block_on(async {
            tokio::select! {
                result = run_client(&config) => {
                    match result {
                        Ok(code) => {
                            info!("Client exited with code: {}", code);
                        }
                        Err(e) => {
                            error!("Client error: {:?}", e);
                        }
                    }
                }
                _ = async {
                    let _ = shutdown_rx.await;
                } => {
                    info!("Client shutdown requested");
                }
            }
        });

        IS_RUNNING.store(false, Ordering::SeqCst);
        info!("Client thread exited");
    });

    // Store the handle after spawning the thread
    {
        let mut state = get_client_state().lock().unwrap();
        *state = Some(ClientHandle {
            shutdown_tx: Some(shutdown_tx),
            thread_handle: Some(thread_handle),
        });
    }

    // Give the client a moment to start
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Check if still running (it might have failed immediately)
    if !IS_RUNNING.load(Ordering::SeqCst) {
        error!("Client failed to start");
        return -11;
    }

    info!("Client started successfully");
    0
}

/// Stop the slipstream client.
#[no_mangle]
pub unsafe extern "C" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeStopSlipstreamClient(
    _env: JNIEnv,
    _class: JClass,
) {
    init_android_logging();
    info!("nativeStopSlipstreamClient called");

    let handle = {
        let mut state = get_client_state().lock().unwrap();
        state.take()
    };

    if let Some(mut handle) = handle {
        // Send shutdown signal
        if let Some(tx) = handle.shutdown_tx.take() {
            let _ = tx.send(());
            info!("Client stop signal sent");
        }

        // Wait for the thread to finish (with timeout)
        if let Some(thread_handle) = handle.thread_handle.take() {
            info!("Waiting for client thread to exit...");
            // Wait up to 3 seconds for the thread to exit
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(3);

            loop {
                if !IS_RUNNING.load(Ordering::SeqCst) {
                    break;
                }
                if start.elapsed() > timeout {
                    warn!("Timeout waiting for client thread to exit");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }

            // Try to join the thread (non-blocking if it already exited)
            match thread_handle.join() {
                Ok(()) => info!("Client thread joined successfully"),
                Err(_) => warn!("Client thread panicked"),
            }
        }

        IS_RUNNING.store(false, Ordering::SeqCst);
        info!("Client stopped");
    } else {
        warn!("No client running to stop");
    }
}

/// Check if the slipstream client is running.
#[no_mangle]
pub unsafe extern "C" fn Java_app_slipnet_tunnel_SlipstreamBridge_nativeIsClientRunning(
    _env: JNIEnv,
    _class: JClass,
) -> jboolean {
    if IS_RUNNING.load(Ordering::SeqCst) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}
