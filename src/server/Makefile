## Haiku Generic Makefile v2.6 ##
##
## Builds the Sotoportego daemon (sotoportego_server).

# The name of the binary.
NAME = sotoportego_server

# The type of binary, must be one of:
#	APP:	Application
#	SHARED:	Shared library or add-on
#	STATIC:	Static library archive
#	DRIVER: Kernel driver
TYPE = APP

# If you plan to use localization, specify the application's MIME signature.
APP_MIME_SIG = application/x-vnd.VePro-SotoportegoServer

# Source files. Shared code under common/ and the backends under backend/ are
# compiled straight into the daemon.
SRCS = \
	main.cpp \
	SotoportegoServer.cpp \
	ProfileStore.cpp \
	GeoLookup.cpp \
	VPNGateFetcher.cpp \
	../backend/VPNBackend.cpp \
	../backend/OpenVPNBackend.cpp \
	../backend/OpenVPNManagement.cpp \
	../backend/TunDevice.cpp \
	../backend/WireGuardBackend.cpp \
	../backend/WireGuardCrypto.cpp \
	../backend/tailscale/TailscaleBackend.cpp \
	../backend/tailscale/TSIdentity.cpp \
	../backend/tailscale/TSNoise.cpp \
	../backend/tailscale/TSControl.cpp \
	../backend/tailscale/TSControlClient.cpp \
	../backend/tailscale/TSControlConn.cpp \
	../backend/tailscale/TSControlSession.cpp \
	../backend/tailscale/TSHttp2.cpp \
	../backend/tailscale/TSHpack.cpp \
	../backend/tailscale/TSRegister.cpp \
	../backend/tailscale/TSMap.cpp \
	../backend/tailscale/TSJson.cpp \
	../backend/tailscale/TSNetmap.cpp \
	../backend/tailscale/NaClBox.cpp \
	../backend/tailscale/TSStun.cpp \
	../backend/tailscale/TSDisco.cpp \
	../backend/tailscale/TSDerp.cpp \
	../backend/tailscale/MagicSock.cpp \
	../backend/tailscale/WGPeer.cpp \
	../backend/tailscale/PeerPath.cpp \
	../backend/tailscale/TSMagicDns.cpp \
	../backend/tailscale/TSPeerSet.cpp \
	../backend/tailscale/TSSessionState.cpp \
	../backend/tailscale/TSTls.cpp \
	../common/OpenVPNConfigParser.cpp \
	../common/WireGuardConfigParser.cpp \
	../common/WireGuardRoutes.cpp \
	../common/CountryCentroids.cpp \
	../common/TSConfig.cpp \
	../common/VPNProfile.cpp \
	../common/VPNState.cpp \
	../common/VPNStats.cpp

# Resource definition files. NOTE: the variable read by makefile-engine is
# RDEFS (plural); using the wrong name silently skips the resource compile.
RDEFS = Sotoportego_server.rdef
RSRCS =

# Libraries to link against. libbe provides BApplication / BMessage / etc.;
# libnetwork carries the POSIX socket API the backends use; libcrypto (OpenSSL)
# provides X25519 and ChaCha20-Poly1305 for the WireGuard handshake; libssl is
# the TLS client transport for the Tailscale control channel and DERP.
# $(STDCPPLIBS) pulls in libstdc++/libsupc++ — the makefile-engine links with
# `cc`, which does not add the C++ runtime itself.
LIBS = be network crypto ssl $(STDCPPLIBS)

# Additional paths to directories following the standard libXXX.so layout.
LIBPATHS =

# Additional paths to look for system headers.
SYSTEM_INCLUDE_PATHS =

# Additional paths to look for local headers.
LOCAL_INCLUDE_PATHS = ../common ../backend ../backend/tailscale

# Level of optimization: none, some, full.
OPTIMIZE := some

# Locales.
LOCALES =

# Preprocessor symbols to define.
DEFINES =

# Warning level: none, all.
WARNINGS = all

# Keep debugging symbols in the image (yes/no via SYMBOLS/DEBUGGER).
SYMBOLS :=
DEBUGGER :=

# Extra compiler/linker flags.
COMPILER_FLAGS =
LINKER_FLAGS =

# The version of the application.
APP_VERSION :=

# (DRIVER only) where the driver lives.
DRIVER_PATH =

## Include the Makefile-Engine.
DEVEL_DIRECTORY := \
	$(shell findpaths -r "makefile_engine" B_FIND_PATH_DEVELOP_DIRECTORY)
include $(DEVEL_DIRECTORY)/etc/makefile-engine
