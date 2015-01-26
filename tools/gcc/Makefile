
GCCPLUGINS_DIR := $(shell $(CC) -print-file-name=plugin)

ifeq ($(PLUGINCC),$(HOSTCC))
HOSTLIBS := hostlibs
HOST_EXTRACFLAGS += -I$(GCCPLUGINS_DIR)/include -I$(src)
export HOST_EXTRACFLAGS
else
HOSTLIBS := hostcxxlibs
HOST_EXTRACXXFLAGS += -I$(GCCPLUGINS_DIR)/include -I$(src)
export HOST_EXTRACXXFLAGS
endif

export GCCPLUGINS_DIR HOSTLIBS

$(HOSTLIBS)-y := fuzz_instrument.so

always := $($(HOSTLIBS)-y)

fuzz_instrument-objs := fuzz_instrument.o
