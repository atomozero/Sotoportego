## Haiku Generic Makefile v2.6 ##
##
## Builds the Sotoportego CLI test client (sotoportego_cli).

# The name of the binary.
NAME = sotoportego_cli

# The type of binary, must be one of:
#	APP:	Application
#	SHARED:	Shared library or add-on
#	STATIC:	Static library archive
#	DRIVER: Kernel driver
TYPE = APP

# If you plan to use localization, specify the application's MIME signature.
APP_MIME_SIG = application/x-vnd.VePro-SotoportegoCLI

# Source files. The client only needs the shared protocol/value types; it never
# links the backends (those live in the daemon).
SRCS = \
	main.cpp \
	../common/VPNProfile.cpp \
	../common/VPNState.cpp \
	../common/VPNStats.cpp

# Resource definition files.
RDEF = Sotoportego_cli.rdef
RSRC =

# Libraries to link against.
LIBS = be

# Additional paths to directories following the standard libXXX.so layout.
LIBPATHS =

# Additional paths to look for system headers.
SYSTEM_INCLUDE_PATHS =

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
