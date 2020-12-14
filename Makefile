ifeq ($(RTE_SDK),)
	$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overridden by command line or environment
RTE_TARGET ?= x86_64-native-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP=dpdkcap

# all source are stored in SRCS-y
SRC_DIR = ./src
SOURCES = main.c ddosDetectCore.c featureExtractCore.c featureUpdateCore.c packetCaptureCore.c util.c feature.c
# SOURCES = main.c $(wildcard ./$(SRC_DIR)/*.c)

# debug:
# 	@echo '$(addprefix $(SRC_DIR)/, $(SOURCES))'

SRCS-y += $(addprefix $(SRC_DIR)/, $(SOURCES))

CFLAGS += -O3 -g $(WERROR_FLAGS) -Wfatal-errors -std=c99 -U__STRICT_ANSI__
LDLIBS += -lncurses

include $(RTE_SDK)/mk/rte.extapp.mk