sm := ta_arm32
sm-ta_arm32 := y
CFG_ARM32_ta_arm32 := y
ta_arm32-platform-cppflags := -DARM32=1 -D__ILP32__=1
ta_arm32-platform-cflags := -mcpu=cortex-a53 -Os -g3 -fpic -mthumb -fno-short-enums -fno-common -mno-unaligned-access -mfloat-abi=hard -funsafe-math-optimizations -funwind-tables
ta_arm32-platform-aflags := -pipe -g -mcpu=cortex-a53 -marm
CFG_TA_FLOAT_SUPPORT := y
CFG_CACHE_API := y
CFG_SECURE_DATA_PATH := n
CFG_TA_MBEDTLS_SELF_TEST := n
CFG_TA_MBEDTLS := y
CFG_TA_MBEDTLS_MPI := y
CFG_SYSTEM_PTA := y
CFG_TA_DYNLINK := y
CFG_TEE_TA_LOG_LEVEL := 1
CFG_FTRACE_SUPPORT := n
CFG_UNWIND := y
CFG_TA_MBEDTLS := y
CFG_REE_FS_TA_AML := y
CROSS_COMPILE ?= arm-linux-gnueabihf-
CROSS_COMPILE32 ?= $(CROSS_COMPILE)
CROSS_COMPILE_ta_arm32 ?= $(CROSS_COMPILE32)
COMPILER ?= gcc
COMPILER_ta_arm32 ?= $(COMPILER)

