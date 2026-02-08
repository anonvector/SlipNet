/*
 * JNI wrapper for hev-socks5-tunnel
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <android/log.h>

#include "../hev-socks5-tunnel-src/include/hev-socks5-tunnel.h"

#define LOG_TAG "HevTunnel"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static pthread_t tunnel_thread;
static volatile int tunnel_running = 0;
static char *config_content = NULL;
static int tun_fd_global = -1;

static void *tunnel_thread_func(void *arg) {
    LOGI("Tunnel thread started");

    int result = hev_socks5_tunnel_main_from_str(
        (const unsigned char *)config_content,
        strlen(config_content),
        tun_fd_global
    );

    LOGI("Tunnel thread exited with result: %d", result);
    tunnel_running = 0;

    return NULL;
}

JNIEXPORT jint JNICALL
Java_app_slipnet_tunnel_HevSocks5Tunnel_nativeStart(
    JNIEnv *env,
    jclass clazz,
    jstring config,
    jint tun_fd
) {
    if (tunnel_running) {
        LOGE("Tunnel already running");
        return -1;
    }

    const char *config_str = (*env)->GetStringUTFChars(env, config, NULL);
    if (!config_str) {
        LOGE("Failed to get config string");
        return -1;
    }

    // Free old config if exists
    if (config_content) {
        free(config_content);
    }

    // Copy config
    config_content = strdup(config_str);
    (*env)->ReleaseStringUTFChars(env, config, config_str);

    if (!config_content) {
        LOGE("Failed to allocate config memory");
        return -1;
    }

    tun_fd_global = tun_fd;
    tunnel_running = 1;

    LOGI("Starting tunnel with fd=%d", tun_fd);
    LOGI("Config:\n%s", config_content);

    int ret = pthread_create(&tunnel_thread, NULL, tunnel_thread_func, NULL);
    if (ret != 0) {
        LOGE("Failed to create tunnel thread: %d", ret);
        tunnel_running = 0;
        free(config_content);
        config_content = NULL;
        return -1;
    }

    LOGI("Tunnel started successfully");
    return 0;
}

JNIEXPORT void JNICALL
Java_app_slipnet_tunnel_HevSocks5Tunnel_nativeStop(
    JNIEnv *env,
    jclass clazz
) {
    if (!tunnel_running) {
        LOGI("Tunnel not running");
        return;
    }

    LOGI("Stopping tunnel...");
    hev_socks5_tunnel_quit();

    // Wait for thread to finish
    pthread_join(tunnel_thread, NULL);

    if (config_content) {
        free(config_content);
        config_content = NULL;
    }

    tunnel_running = 0;
    tun_fd_global = -1;
    LOGI("Tunnel stopped");
}

JNIEXPORT void JNICALL
Java_app_slipnet_tunnel_HevSocks5Tunnel_nativeSetRejectQuic(
    JNIEnv *env,
    jclass clazz,
    jboolean enabled
) {
    hev_socks5_tunnel_set_reject_quic(enabled ? 1 : 0);
}

JNIEXPORT jboolean JNICALL
Java_app_slipnet_tunnel_HevSocks5Tunnel_nativeIsRunning(
    JNIEnv *env,
    jclass clazz
) {
    return tunnel_running ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jlongArray JNICALL
Java_app_slipnet_tunnel_HevSocks5Tunnel_nativeGetStats(
    JNIEnv *env,
    jclass clazz
) {
    size_t tx_packets = 0, tx_bytes = 0, rx_packets = 0, rx_bytes = 0;

    if (tunnel_running) {
        hev_socks5_tunnel_stats(&tx_packets, &tx_bytes, &rx_packets, &rx_bytes);
    }

    jlongArray result = (*env)->NewLongArray(env, 4);
    if (result) {
        jlong stats[4] = {
            (jlong)tx_packets,
            (jlong)tx_bytes,
            (jlong)rx_packets,
            (jlong)rx_bytes
        };
        (*env)->SetLongArrayRegion(env, result, 0, 4, stats);
    }

    return result;
}
