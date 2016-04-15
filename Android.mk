LOCAL_PATH:= $(call my-dir)/

include $(CLEAR_VARS)

LOCAL_LDLIBS := -lz
LOCAL_C_INCLUDES := openssl/include lzo/include openssl/crypto openssl vpnconnect/src/compat vpnconnect/src/vpnconnect vpnconnect/include google-breakpad/src google-breakpad/src/common/android/include polarssl/include vpnconnect/android-config/




LOCAL_CFLAGS= -DHAVE_CONFIG_H -DTARGET_ABI=\"${TARGET_ABI}\"
LOCAL_STATIC_LIBRARIES :=  liblzo-static

ifeq ($(WITH_POLAR),1)
LOCAL_STATIC_LIBRARIES +=  polarssl-static
LOCAL_CFLAGS += -DENABLE_CRYPTO_POLARSSL=1
else
#LOCAL_SHARED_LIBRARIES :=  libssl libcrypto
LOCAL_STATIC_LIBRARIES +=  libssl_static libcrypto_static
LOCAL_CFLAGS += -DENABLE_CRYPTO_OPENSSL=1
endif

ifeq ($(WITH_BREAKPAD),1)
LOCAL_STATIC_LIBRARIES += breakpad_client
LOCAL_CFLAGS += -DGOOGLE_BREAKPAD=1
endif

LOCAL_MODULE = vpnconnect



LOCAL_SRC_FILES:= \
	src/compat/compat-basename.c \
	src/compat/compat-daemon.c \
	src/compat/compat-dirname.c \
	src/compat/compat-gettimeofday.c \
	src/compat/compat-inet_ntop.c \
	src/compat/compat-inet_pton.c \
	src/compat/compat-lz4.c \
	src/vpnconnect/base64.c \
	src/vpnconnect/buffer.c \
	src/vpnconnect/clinat.c \
	src/vpnconnect/console.c \
	src/vpnconnect/crypto.c \
	src/vpnconnect/crypto_openssl.c \
	src/vpnconnect/crypto_polarssl.c \
	src/vpnconnect/cryptoapi.c \
	src/vpnconnect/dhcp.c \
	src/vpnconnect/error.c \
	src/vpnconnect/event.c \
	src/vpnconnect/fdmisc.c \
	src/vpnconnect/forward.c \
	src/vpnconnect/fragment.c \
	src/vpnconnect/gremlin.c \
	src/vpnconnect/helper.c \
	src/vpnconnect/httpdigest.c \
	src/vpnconnect/init.c \
	src/vpnconnect/interval.c \
	src/vpnconnect/list.c \
	src/vpnconnect/lladdr.c \
	src/vpnconnect/lzo.c \
	src/vpnconnect/manage.c \
	src/vpnconnect/mbuf.c \
	src/vpnconnect/misc.c \
	src/vpnconnect/mroute.c \
	src/vpnconnect/mss.c \
	src/vpnconnect/mstats.c \
	src/vpnconnect/mtcp.c \
	src/vpnconnect/mtu.c \
	src/vpnconnect/mudp.c \
	src/vpnconnect/multi.c \
	src/vpnconnect/ntlm.c \
	src/vpnconnect/occ.c \
	src/vpnconnect/vpnconnect.c \
	src/vpnconnect/options.c \
	src/vpnconnect/otime.c \
	src/vpnconnect/packet_id.c \
	src/vpnconnect/perf.c \
	src/vpnconnect/pf.c \
	src/vpnconnect/ping.c \
	src/vpnconnect/pkcs11.c \
	src/vpnconnect/pkcs11_openssl.c \
	src/vpnconnect/platform.c \
	src/vpnconnect/plugin.c \
	src/vpnconnect/pool.c \
	src/vpnconnect/proto.c \
	src/vpnconnect/proxy.c \
	src/vpnconnect/ps.c \
	src/vpnconnect/push.c \
	src/vpnconnect/reliable.c \
	src/vpnconnect/route.c \
	src/vpnconnect/schedule.c \
	src/vpnconnect/session_id.c \
	src/vpnconnect/shaper.c \
	src/vpnconnect/sig.c \
	src/vpnconnect/socket.c \
	src/vpnconnect/socks.c \
	src/vpnconnect/ssl.c \
	src/vpnconnect/ssl_openssl.c \
	src/vpnconnect/ssl_polarssl.c \
	src/vpnconnect/ssl_verify.c \
	src/vpnconnect/ssl_verify_openssl.c \
	src/vpnconnect/ssl_verify_polarssl.c \
	src/vpnconnect/status.c \
	src/vpnconnect/tun.c \
	src/vpnconnect/comp-lz4.c \
	src/vpnconnect/comp.c \
	src/vpnconnect/compstub.c \


ifeq ($(WITH_BREAKPAD),1)
LOCAL_SRC_FILES+=src/vpnconnect/breakpad.cpp
endif


include $(BUILD_SHARED_LIBRARY)
#include $(BUILD_EXECUTABLE)
