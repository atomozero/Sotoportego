## Haiku Generic Makefile v2.6 ##
##
## Builds the Sotoportego GUI client (Sotoportego).

# The name of the binary.
NAME = Sotoportego

# The type of binary, must be one of:
#	APP:	Application
#	SHARED:	Shared library or add-on
#	STATIC:	Static library archive
#	DRIVER: Kernel driver
TYPE = APP

# If you plan to use localization, specify the application's MIME signature.
APP_MIME_SIG = application/x-vnd.VePro-Sotoportego

# Source files. The GUI is a client of the daemon; it needs the shared
# protocol/value types but never links the backends.
SRCS = \
	main.cpp \
	SotoportegoApp.cpp \
	MainWindow.cpp \
	HeaderView.cpp \
	CredentialsWindow.cpp \
	MetricPill.cpp \
	VaporettoWindow.cpp \
	DeskbarIcon.cpp \
	MapView.cpp \
	VPNMapWindow.cpp \
	TileCache.cpp \
	CoastlineData.cpp \
	../common/OpenVPNConfigParser.cpp \
	../common/VPNProfile.cpp \
	../common/VPNState.cpp \
	../common/VPNStats.cpp

# Resource definition files. NOTE: the variable read by makefile-engine is
# RDEFS (plural); using the wrong name silently skips the resource compile.
RDEFS = Sotoportego.rdef
RSRCS =

# Libraries to link against. The GUI needs the Interface Kit (libbe) plus the
# Layout Kit, which also lives in libbe. libtracker provides BFilePanel
# (used by the .ovpn import flow). $(STDCPPLIBS) pulls in libstdc++/libsupc++
# — the makefile-engine links with `cc`, which does not add the C++ runtime
# itself.
LIBS = be tracker translation columnlistview $(STDCPPLIBS)

# Additional paths to directories following the standard libXXX.so layout.
LIBPATHS =

# Additional paths to look for system headers. BAboutWindow lives under the
# private interface headers (its implementation is in libbe).
SYSTEM_INCLUDE_PATHS = /system/develop/headers/private/interface

# Additional paths to look for local headers.
LOCAL_INCLUDE_PATHS = ../common

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
