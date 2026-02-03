# Android.mk for hev-socks5-tunnel JNI wrapper

MY_LOCAL_PATH := $(call my-dir)

# Include hev-socks5-tunnel
include $(MY_LOCAL_PATH)/hev-socks5-tunnel-src/Android.mk

# Build JNI wrapper
LOCAL_PATH := $(MY_LOCAL_PATH)
include $(CLEAR_VARS)

LOCAL_MODULE := hev-tunnel-jni
LOCAL_SRC_FILES := hev-socks5-tunnel/hev_jni.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/hev-socks5-tunnel-src/include
LOCAL_SHARED_LIBRARIES := hev-socks5-tunnel
LOCAL_LDLIBS := -llog
LOCAL_LDFLAGS += -Wl,-z,max-page-size=16384
LOCAL_LDFLAGS += -Wl,-z,common-page-size=16384

include $(BUILD_SHARED_LIBRARY)
