CONTIKI_PROJECT = da-ahe-node
all: $(CONTIKI_PROJECT)

# Pin the firmware version string so source archives build without .git.
RELSTR = 4.8-9771e9a

# GCC 13's libnosys emits informational syscall warnings. Keep them visible,
# but do not turn those vendor-library warnings into linker failures.
LDFLAGS_WERROR =

CONTIKI ?= ../../../contiki-ng

MODULES_REL += src
MODULES_REL += third_party/pqclean_common
MODULES_REL += third_party/ml_dsa_44
MODULES_SOURCES_EXCLUDES += da-ahe-node.c

include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_APP_LAYER_DIR)/coap

CFLAGS += -std=c99 -Os
CFLAGS += -Wno-array-bounds
CFLAGS += -DDA_AHE_NO_HEAP=1
LDFLAGS += -Wl,-Map=$(CONTIKI_NG_PROJECT_MAP),--cref,--allow-multiple-definition

include $(CONTIKI)/Makefile.include
