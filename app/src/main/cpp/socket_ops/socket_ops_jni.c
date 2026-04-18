/*
 * JNI helpers for socket-level DPI bypass primitives:
 *   - setIpTtl(fd, ttl): raw setsockopt(IP_TTL / IPV6_UNICAST_HOPS)
 *   - sendFakeThenSwap(fd, fakeBytes, realBytes, lowTtl, normalTtl):
 *       Sends `fakeBytes` with TTL=lowTtl (so it dies mid-path before reaching
 *       the server), then swaps the kernel's send-buffer pages to contain
 *       `realBytes` so any TCP retransmit carries real data.
 *
 * The fake-swap trick exploits splice(SPLICE_F_GIFT): pages gifted into the
 * socket send queue remain mapped in this process's address space; writing
 * through that mapping modifies the exact pages the kernel will retransmit.
 * This is the same mechanism ByeDPI uses on Linux.
 */

#include <jni.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <android/log.h>

#define LOG_TAG "SlipNetSockOps"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

#ifndef SPLICE_F_GIFT
#define SPLICE_F_GIFT 8
#endif

static int set_ttl_both(int fd, int ttl) {
    int v = ttl;
    int rc_v4 = setsockopt(fd, IPPROTO_IP, IP_TTL, &v, sizeof(v));
    int rc_v6 = setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v, sizeof(v));
    // Success if either worked (IPv4 socket rejects IPv6 opt and vice versa).
    if (rc_v4 == 0 || rc_v6 == 0) return 0;
    return -errno;
}

JNIEXPORT jint JNICALL
Java_app_slipnet_tunnel_NativeSocket_nativeSetIpTtl(
        JNIEnv *env, jclass clazz, jint fd, jint ttl) {
    return set_ttl_both(fd, ttl);
}

/*
 * Cap the outgoing TCP MSS. After connect() the kernel honors this as the
 * upper bound on segment size it sends; combined with TCP_NODELAY and
 * per-write flushes, it forces the tunnel writes into many small segments
 * so DPI that reassembles by TCP segment (without reassembling TLS
 * records) cannot see a contiguous SNI.
 *
 * Returns 0 on success, -errno on failure (caller should treat failure as
 * non-fatal and continue with whatever MSS the handshake negotiated).
 */
JNIEXPORT jint JNICALL
Java_app_slipnet_tunnel_NativeSocket_nativeSetTcpMaxSeg(
        JNIEnv *env, jclass clazz, jint fd, jint mss) {
    if (fd < 0 || mss < 40) return -EINVAL;
    int v = mss;
    if (setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &v, sizeof(v)) < 0) {
        return -errno;
    }
    return 0;
}

/*
 * sendFakeThenSwap: low-TTL fake send with kernel-buffer swap.
 *
 * Steps:
 *   1. Allocate an anonymous mmap region sized to fakeLen.
 *   2. memcpy fake bytes into it.
 *   3. setsockopt TTL=lowTtl.
 *   4. vmsplice(SPLICE_F_GIFT) the mmap region into a pipe.
 *   5. splice the pipe into the socket (kernel sk_buff now references the
 *      mmap pages by reference; send is on the wire with low TTL).
 *   6. setsockopt TTL=normalTtl.
 *   7. memcpy real bytes over the mmap region. The kernel's sk_buff still
 *      holds refs to those pages — so any TCP retransmit now reads the
 *      real bytes instead of the fake.
 *   8. munmap and close the pipe. (The kernel retains its own page refs.)
 *
 * Returns bytes spliced, or negative errno on failure.
 *
 * Requirement: fakeLen == realLen. Caller pads/truncates as needed.
 */
JNIEXPORT jint JNICALL
Java_app_slipnet_tunnel_NativeSocket_nativeSendFakeThenSwap(
        JNIEnv *env, jclass clazz,
        jint fd,
        jbyteArray fake, jbyteArray real,
        jint low_ttl, jint normal_ttl) {

    if (!fake || !real) return -EINVAL;
    jsize fake_len = (*env)->GetArrayLength(env, fake);
    jsize real_len = (*env)->GetArrayLength(env, real);
    if (fake_len <= 0 || fake_len != real_len) return -EINVAL;

    long page_size = sysconf(_SC_PAGE_SIZE);
    if (page_size <= 0) page_size = 4096;
    size_t alloc_size = ((size_t)fake_len + page_size - 1) & ~((size_t)page_size - 1);

    void *buf = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        LOGE("mmap failed: %s", strerror(errno));
        return -errno;
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        int e = errno;
        munmap(buf, alloc_size);
        LOGE("pipe failed: %s", strerror(e));
        return -e;
    }

    jbyte *fake_ptr = (*env)->GetByteArrayElements(env, fake, NULL);
    jbyte *real_ptr = (*env)->GetByteArrayElements(env, real, NULL);
    if (!fake_ptr || !real_ptr) {
        if (fake_ptr) (*env)->ReleaseByteArrayElements(env, fake, fake_ptr, JNI_ABORT);
        if (real_ptr) (*env)->ReleaseByteArrayElements(env, real, real_ptr, JNI_ABORT);
        close(pipefd[0]); close(pipefd[1]);
        munmap(buf, alloc_size);
        return -ENOMEM;
    }

    memcpy(buf, fake_ptr, fake_len);

    if (set_ttl_both(fd, low_ttl) < 0) {
        int e = errno;
        LOGW("set low TTL failed: %s", strerror(e));
        // Non-fatal: continue; without TTL the fake will reach the server.
    }

    struct iovec iov = { .iov_base = buf, .iov_len = (size_t)fake_len };
    ssize_t vsp = syscall(__NR_vmsplice, pipefd[1], &iov, 1UL, (unsigned int)SPLICE_F_GIFT);
    if (vsp != (ssize_t)fake_len) {
        int e = errno;
        LOGE("vmsplice returned %zd (expected %d): %s", vsp, fake_len, strerror(e));
        set_ttl_both(fd, normal_ttl);
        (*env)->ReleaseByteArrayElements(env, fake, fake_ptr, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, real, real_ptr, JNI_ABORT);
        close(pipefd[0]); close(pipefd[1]);
        munmap(buf, alloc_size);
        return vsp < 0 ? -e : -EIO;
    }

    ssize_t spliced = splice(pipefd[0], NULL, fd, NULL, (size_t)fake_len, 0);
    if (spliced < 0) {
        int e = errno;
        LOGE("splice failed: %s", strerror(e));
        set_ttl_both(fd, normal_ttl);
        (*env)->ReleaseByteArrayElements(env, fake, fake_ptr, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, real, real_ptr, JNI_ABORT);
        close(pipefd[0]); close(pipefd[1]);
        munmap(buf, alloc_size);
        return -e;
    }

    // Restore TTL BEFORE the buffer swap to minimize the window where a
    // retransmit could fire with low TTL.
    set_ttl_both(fd, normal_ttl);

    // Swap: overwrite the gifted pages with real data. The kernel's sk_buff
    // references these same pages; on retransmit it reads the real bytes.
    memcpy(buf, real_ptr, real_len);

    (*env)->ReleaseByteArrayElements(env, fake, fake_ptr, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, real, real_ptr, JNI_ABORT);
    close(pipefd[0]);
    close(pipefd[1]);
    munmap(buf, alloc_size);

    return (jint)spliced;
}
