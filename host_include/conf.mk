# auto-generated TEE configuration file
# TEE version ATOS-V3.8.0-9ca2dd66a
ARCH=arm
PLATFORM=meson
PLATFORM_FLAVOR=sc2
CFG_AES_GCM_TABLE_BASED=n
CFG_AE_DECRYPT=n
CFG_ARM32_core=y
CFG_ARM32_ldelf=y
CFG_ARM32_ta_arm32=y
CFG_ASLR_SEED=0x1f800000
CFG_ATOS_IMPL_VERSION=0
CFG_AUCPU_FW_WORK_RAM_SIZE=0x20000
CFG_BOOT_SECONDARY_REQUEST=n
CFG_CACHE_API=y
CFG_CC_OPTIMIZE_FOR_SIZE=y
CFG_CIPHER_DECRYPT=y
CFG_CONCURRENT_SINGLE_INSTANCE_TA=y
CFG_CORE_ASLR=y
CFG_CORE_BGET_BESTFIT=y
CFG_CORE_BIGNUM_MAX_BITS=4096
CFG_CORE_CLUSTER_SHIFT=2
CFG_CORE_DUMP_OOM=n
CFG_CORE_DYN_SHM=y
CFG_CORE_HEAP_SIZE=65536
CFG_CORE_HUK_SUBKEY_COMPAT=y
CFG_CORE_LARGE_PHYS_ADDR=n
CFG_CORE_MBEDTLS_MPI=y
CFG_CORE_NEX_HEAP_SIZE=16384
CFG_CORE_RESERVED_SHM=y
CFG_CORE_RODATA_NOEXEC=n
CFG_CORE_RWDATA_NOEXEC=y
CFG_CORE_SANITIZE_KADDRESS=n
CFG_CORE_SANITIZE_UNDEFINED=n
CFG_CORE_THREAD_SHIFT=0
CFG_CORE_TZSRAM_EMUL_SIZE=458752
CFG_CORE_UNMAP_CORE_AT_EL0=y
CFG_CORE_WORKAROUND_NSITR_CACHE_PRIME=y
CFG_CORE_WORKAROUND_SPECTRE_BP=y
CFG_CORE_WORKAROUND_SPECTRE_BP_SEC=y
CFG_CPU_VERSION=y
CFG_CRYPTO=y
CFG_CRYPTOLIB_DIR=core/lib/libtomcrypt
CFG_CRYPTOLIB_NAME=tomcrypt
CFG_CRYPTOLIB_NAME_tomcrypt=y
CFG_CRYPTO_AES=y
CFG_CRYPTO_AES_AML=n
CFG_CRYPTO_AES_ARM32_CE=y
CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB=n
CFG_CRYPTO_CBC=y
CFG_CRYPTO_CBC_MAC=y
CFG_CRYPTO_CCM=y
CFG_CRYPTO_CMAC=y
CFG_CRYPTO_CONCAT_KDF=y
CFG_CRYPTO_CTR=y
CFG_CRYPTO_CTS=y
CFG_CRYPTO_DES=y
CFG_CRYPTO_DES_AML=n
CFG_CRYPTO_DH=y
CFG_CRYPTO_DSA=y
CFG_CRYPTO_ECB=y
CFG_CRYPTO_ECC=y
CFG_CRYPTO_GCM=y
CFG_CRYPTO_GCM_AML=n
CFG_CRYPTO_HKDF=y
CFG_CRYPTO_HMAC=y
CFG_CRYPTO_HMAC_AML=n
CFG_CRYPTO_INTERNAL_TEST=n
CFG_CRYPTO_MD5=y
CFG_CRYPTO_PBKDF2=y
CFG_CRYPTO_RAM_SIZE=0x100000
CFG_CRYPTO_RSA=y
CFG_CRYPTO_RSASSA_NA1=y
CFG_CRYPTO_SHA1=y
CFG_CRYPTO_SHA1_AML=n
CFG_CRYPTO_SHA1_ARM32_CE=y
CFG_CRYPTO_SHA224=y
CFG_CRYPTO_SHA224_AML=n
CFG_CRYPTO_SHA256=y
CFG_CRYPTO_SHA256_AML=n
CFG_CRYPTO_SHA256_ARM32_CE=y
CFG_CRYPTO_SHA384=y
CFG_CRYPTO_SHA512=y
CFG_CRYPTO_SHA512_256=y
CFG_CRYPTO_SIZE_OPTIMIZATION=y
CFG_CRYPTO_SM2_DSA=y
CFG_CRYPTO_SM2_KEP=y
CFG_CRYPTO_SM2_PKE=y
CFG_CRYPTO_SM3=y
CFG_CRYPTO_SM4=y
CFG_CRYPTO_WITH_CE=y
CFG_CRYPTO_XTS=y
CFG_DEBUG=n
CFG_DEBUG_INFO=y
CFG_DEMUX=y
CFG_DEVICE_ENUM_PTA=y
CFG_DEVICE_KEY=y
CFG_DMC=y
CFG_DMC_V3=y
CFG_DOLBY_QUERY=y
CFG_DRAM0_BASE=0x10000000
CFG_DRAM0_SIZE=0xe0000000
CFG_DT=y
CFG_DTB_MAX_SIZE=0x3000
CFG_DT_ADDR=0x0
CFG_EARLY_TA=n
CFG_EFUSE=y
CFG_EFUSE_LAYOUT=n
CFG_EFUSE_READ_ALL_WRITE_BLOCK=y
CFG_EMBED_DTB=y
CFG_EMBED_DTB_SOURCE_FILE=amlogic-tee.dts
CFG_EMBED_PERM_SOURCE_FILE=default_perm.txt
CFG_ENABLE_SCTLR_RR=n
CFG_ENABLE_SCTLR_Z=n
CFG_EXTERNAL_DTB_OVERLAY=n
CFG_FTRACE_SUPPORT=n
CFG_FTRACE_US_MS=10000
CFG_GENERIC_BOOT=y
CFG_GP_SOCKETS=n
CFG_HDCP=y
CFG_HDCP_DEBUG=n
CFG_HWSUPP_MEM_PERM_PXN=y
CFG_HWSUPP_MEM_PERM_WXN=y
CFG_HWSUPP_PMULT_64=y
CFG_HW_KL=n
CFG_HW_KL_TEST=n
CFG_HW_RAMDOM_STACK_GUARD=y
CFG_KDF_MKL=y
CFG_KDF_MKL_MSR=n
CFG_KDF_MKL_TEST=n
CFG_KERN_LINKER_ARCH=arm
CFG_KERN_LINKER_FORMAT=elf32-littlearm
CFG_KEYMASTER=y
CFG_KEYTABLE=y
CFG_KEY_DEBUG=n
CFG_LIBUTILS_WITH_ISOC=y
CFG_LOCKDEP=n
CFG_LOGGER=y
CFG_LOG_SHMEM_SIZE=0x00040000
CFG_LOG_SHMEM_START=(CFG_SHMEM_START + CFG_SHMEM_SIZE - CFG_LOG_SHMEM_SIZE)
CFG_LPAE_ADDR_SPACE_SIZE=(1ull << 32)
CFG_LTC_OPTEE_THREAD=y
CFG_MAILBOX=y
CFG_MESON_UART=y
CFG_MMAP_REGIONS=24
CFG_MSG_LONG_PREFIX_MASK=0x1a
CFG_NUM_THREADS=16
CFG_OPTEE_REVISION_MAJOR=3
CFG_OPTEE_REVISION_MINOR=8
CFG_OS_REV_REPORTS_GIT_SHA1=y
CFG_OTP_LIC=n
CFG_OTP_SUPPORT=y
CFG_PAGED_USER_TA=n
CFG_PCPK_FROM_MKL=y
CFG_PM_STUBS=y
CFG_REE_CALLBACK=n
CFG_REE_FS=y
CFG_REE_FS_HASH_VERIFY=n
CFG_REE_FS_TA=n
CFG_REE_FS_TA_AML=y
CFG_REE_FS_TA_BUFFERED=n
CFG_REG_DEBUG=n
CFG_REK_FROM_MKL=y
CFG_RESERVED_VASPACE_SIZE=(1024 * 1024 * 10)
CFG_RNG_API=n
CFG_RNG_V2=y
CFG_RPMB_DRIVER=y
CFG_RPMB_FS=y
CFG_RPMB_FS_DEV_ID=0
CFG_RPMB_FS_FORMAT=n
CFG_RPMB_WRITE_KEY=n
CFG_RSV_RAM_SIZE=0x03000000
CFG_SCS_INFO=y
CFG_SCTLR_ALIGNMENT_CHECK=y
CFG_SECSTOR_TA=n
CFG_SECSTOR_TA_MGMT_PTA=n
CFG_SECURE_CRYPTO_THREAD=3
CFG_SECURE_DATA_PATH=n
CFG_SECURE_TIME_SOURCE_REE=n
CFG_SECURE_TIME_SOURCE_TEE=y
CFG_SHMEM_SIZE=0x00800000
CFG_SHMEM_START=(CFG_TZDRAM_START + CFG_RSV_RAM_SIZE - CFG_SHMEM_SIZE)
CFG_SHM_MMAP_API=n
CFG_SHOW_CONF_ON_BOOT=n
CFG_SM_NO_CYCLE_COUNTING=y
CFG_SYSCALL_FTRACE=n
CFG_SYSCALL_WRAPPERS_MCOUNT=n
CFG_SYSTEM_PTA=y
CFG_SYS_ANTIROLLBACK=y
CFG_S_STORAGE=y
CFG_TA_ANTIROLLBACK=y
CFG_TA_ANTIROLLBACK_DEBUG=n
CFG_TA_ANTIROLLBACK_OTP=n
CFG_TA_ANTIROLLBACK_SW=y
CFG_TA_ASLR=y
CFG_TA_ASLR_MAX_OFFSET_PAGES=128
CFG_TA_ASLR_MIN_OFFSET_PAGES=0
CFG_TA_BIGNUM_MAX_BITS=4096
CFG_TA_CERT_V1=n
CFG_TA_DYNLINK=y
CFG_TA_FLOAT_SUPPORT=y
CFG_TA_GPROF_SUPPORT=n
CFG_TA_MARKETID=n
CFG_TA_MBEDTLS=y
CFG_TA_MBEDTLS_MPI=y
CFG_TA_MBEDTLS_SELF_TEST=n
CFG_TA_MUTEX=n
CFG_TEE_API_VERSION=GPD-1.1-dev
CFG_TEE_CORE_DEBUG=y
CFG_TEE_CORE_EMBED_INTERNAL_TESTS=n
CFG_TEE_CORE_LOG_LEVEL=2
CFG_TEE_CORE_MALLOC_DEBUG=n
CFG_TEE_CORE_NB_CORE=8
CFG_TEE_CORE_TA_TRACE=y
CFG_TEE_FW_IMPL_VERSION=FW_IMPL_UNDEF
CFG_TEE_FW_MANUFACTURER=FW_MAN_UNDEF
CFG_TEE_IMPL_DESCR=OPTEE
CFG_TEE_MANUFACTURER=LINARO
CFG_TEE_RAM_VA_SIZE=0x00100000
CFG_TEE_TA_LOG_LEVEL=1
CFG_TEE_TA_MALLOC_DEBUG=n
CFG_TEE_TIMER=y
CFG_TTBCR_N_VALUE=7
CFG_TVP=y
CFG_TVP_RAM_SIZE=0x01000000
CFG_TVP_RAM_START=(CFG_SHMEM_START - CFG_TVP_RAM_SIZE)
CFG_TZDRAM_SIZE=(CFG_VP9_PROB_RAM_START - CFG_TZDRAM_START)
CFG_TZDRAM_START=0x05300000
CFG_ULIBS_MCOUNT=n
CFG_ULIBS_SHARED=n
CFG_UNIFY_KEY=y
CFG_UNWIND=y
CFG_VENDOR_PROPS=y
CFG_VIDEO_FW_LOAD=y
CFG_VIDFW_RAM_SIZE=0x00100000
CFG_VIDFW_RAM_START=(CFG_TVP_RAM_START - CFG_VIDFW_RAM_SIZE)
CFG_VIRTUALIZATION=n
CFG_VP9_PROB_PROCESS=y
CFG_VP9_PROB_RAM_SIZE=0x20000
CFG_VP9_PROB_RAM_START=(CFG_VIDFW_RAM_START - CFG_VP9_PROB_RAM_SIZE)
CFG_WATERMARK_NEXGUARD=n
CFG_WATERMARK_NEXGUARD_TEST=n
CFG_WATERMARK_VERIMATRIX=n
CFG_WATERMARK_VERIMATRIX_TEST=n
CFG_WERROR=y
CFG_WITH_ARM_TRUSTED_FW=y
CFG_WITH_DEBUG=y
CFG_WITH_PAGER=n
CFG_WITH_SOFTWARE_PRNG=y
CFG_WITH_STACK_CANARIES=y
CFG_WITH_STATS=y
CFG_WITH_STEST=y
CFG_WITH_USER_TA=y
CFG_WITH_VFP=y
