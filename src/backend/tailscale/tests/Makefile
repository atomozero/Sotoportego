# Offline self-test for the Tailscale backend's deterministic modules.
# Build + run:  make test
#
# Covers the crypto (vs published vectors), wire codecs (round-trip) and the
# netmap/peer/DNS/route logic (vs fixtures). The live checks (control handshake,
# STUN, DERP against real servers) are separate and need network.

CXX ?= g++

INCLUDES = -iquote .. -iquote ../.. -iquote ../../../common

SRCS = \
	ts_selftest.cpp \
	../NaClBox.cpp \
	../PeerPath.cpp \
	../TSControl.cpp \
	../TSDisco.cpp \
	../TSHpack.cpp \
	../TSIdentity.cpp \
	../TSMagicDns.cpp \
	../TSNetmap.cpp \
	../TSNoise.cpp \
	../TSPeerSet.cpp \
	../TSStun.cpp \
	../TSJson.cpp \
	../WGPeer.cpp \
	../../WireGuardCrypto.cpp \
	../../../common/TSConfig.cpp

# libbe: BString/BKeyStore/BMessage; libnetwork: socket API pulled in by TSStun;
# libcrypto: OpenSSL X25519/ChaCha used by the reused WireGuard primitives.
LIBS = -lbe -lnetwork -lcrypto -lstdc++ -lsupc++

# The rekey bench only needs the data-plane transport + its crypto; it drives
# session aging through WGPeer's injectable test clock (no network, no waiting).
BENCH_SRCS = \
	ts_rekey_bench.cpp \
	../TSBackoff.cpp \
	../TSRoutes.cpp \
	../WGPeer.cpp \
	../../WireGuardCrypto.cpp \
	../../../common/WireGuardRoutes.cpp

ts_selftest: $(SRCS)
	$(CXX) -o $@ $(SRCS) $(INCLUDES) $(LIBS)

ts_rekey_bench: $(BENCH_SRCS)
	$(CXX) -o $@ $(BENCH_SRCS) $(INCLUDES) $(LIBS)

test: ts_selftest
	./ts_selftest

bench: ts_rekey_bench
	./ts_rekey_bench

# Run both the fixture self-test and the session-lifetime bench.
check: test bench

clean:
	rm -f ts_selftest ts_rekey_bench

.PHONY: test bench check clean
