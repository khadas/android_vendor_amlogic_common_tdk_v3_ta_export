#ifndef _out_arm_plat_meson_include_generated_conf_h_
#define _out_arm_plat_meson_include_generated_conf_h_
#define CFG_AES_GCM_TABLE_BASED 1
/* CFG_AE_DECRYPT is not set */
#define CFG_ARM32_core 1
#define CFG_ARM32_ldelf 1
#define CFG_ARM32_ta_arm32 1
#define CFG_ASLR_SEED 0x1f800000
#define CFG_ATOS_IMPL_VERSION 0
/* CFG_BOOT_SECONDARY_REQUEST is not set */
#define CFG_CACHE_API 1
#define CFG_CC_OPTIMIZE_FOR_SIZE 1
#define CFG_CIPHER_DECRYPT 1
#define CFG_CORE_ASLR 1
#define CFG_CORE_BGET_BESTFIT 1
#define CFG_CORE_BIGNUM_MAX_BITS 4096
#define CFG_CORE_CLUSTER_SHIFT 2
/* CFG_CORE_DUMP_OOM is not set */
#define CFG_CORE_DYN_SHM 1
#define CFG_CORE_HEAP_SIZE 65536
#define CFG_CORE_HUK_SUBKEY_COMPAT 1
/* CFG_CORE_LARGE_PHYS_ADDR is not set */
#define CFG_CORE_MBEDTLS_MPI 1
#define CFG_CORE_NEX_HEAP_SIZE 16384
#define CFG_CORE_RESERVED_SHM 1
/* CFG_CORE_RODATA_NOEXEC is not set */
#define CFG_CORE_RWDATA_NOEXEC 1
/* CFG_CORE_SANITIZE_KADDRESS is not set */
/* CFG_CORE_SANITIZE_UNDEFINED is not set */
#define CFG_CORE_THREAD_SHIFT 0
#define CFG_CORE_TZSRAM_EMUL_SIZE 458752
#define CFG_CORE_UNMAP_CORE_AT_EL0 1
#define CFG_CORE_WORKAROUND_NSITR_CACHE_PRIME 1
#define CFG_CORE_WORKAROUND_SPECTRE_BP 1
#define CFG_CORE_WORKAROUND_SPECTRE_BP_SEC 1
#define CFG_CPU_VERSION 1
#define CFG_CRYPTO 1
#define CFG_CRYPTOLIB_DIR core/lib/libtomcrypt
#define CFG_CRYPTOLIB_NAME tomcrypt
#define CFG_CRYPTOLIB_NAME_tomcrypt 1
#define CFG_CRYPTO_AES 1
#define CFG_CRYPTO_AES_AML 1
/* CFG_CRYPTO_AES_GCM_FROM_CRYPTOLIB is not set */
#define CFG_CRYPTO_CBC 1
#define CFG_CRYPTO_CBC_MAC 1
#define CFG_CRYPTO_CCM 1
#define CFG_CRYPTO_CMAC 1
#define CFG_CRYPTO_CONCAT_KDF 1
#define CFG_CRYPTO_CTR 1
#define CFG_CRYPTO_CTS 1
#define CFG_CRYPTO_DES 1
#define CFG_CRYPTO_DES_AML 1
#define CFG_CRYPTO_DH 1
#define CFG_CRYPTO_DSA 1
#define CFG_CRYPTO_ECB 1
#define CFG_CRYPTO_ECC 1
#define CFG_CRYPTO_GCM 1
/* CFG_CRYPTO_GCM_AML is not set */
#define CFG_CRYPTO_HKDF 1
#define CFG_CRYPTO_HMAC 1
#define CFG_CRYPTO_HMAC_AML 1
/* CFG_CRYPTO_INTERNAL_TEST is not set */
#define CFG_CRYPTO_MD5 1
#define CFG_CRYPTO_PBKDF2 1
#define CFG_CRYPTO_RSA 1
#define CFG_CRYPTO_RSASSA_NA1 1
#define CFG_CRYPTO_SHA1 1
#define CFG_CRYPTO_SHA1_AML 1
#define CFG_CRYPTO_SHA224 1
#define CFG_CRYPTO_SHA224_AML 1
#define CFG_CRYPTO_SHA256 1
#define CFG_CRYPTO_SHA256_AML 1
#define CFG_CRYPTO_SHA384 1
#define CFG_CRYPTO_SHA512 1
#define CFG_CRYPTO_SHA512_256 1
#define CFG_CRYPTO_SIZE_OPTIMIZATION 1
#define CFG_CRYPTO_SM2_DSA 1
#define CFG_CRYPTO_SM2_KEP 1
#define CFG_CRYPTO_SM2_PKE 1
#define CFG_CRYPTO_SM3 1
#define CFG_CRYPTO_SM4 1
#define CFG_CRYPTO_XTS 1
/* CFG_DEBUG is not set */
#define CFG_DEBUG_INFO 1
#define CFG_DEMUX 1
#define CFG_DEVICE_ENUM_PTA 1
#define CFG_DEVICE_KEY 1
#define CFG_DMC 1
#define CFG_DMC_V3 1
/* CFG_DOLBY_QUERY is not set */
#define CFG_DRAM0_BASE 0x10000000
#define CFG_DRAM0_SIZE 0xe0000000
#define CFG_DT 1
#define CFG_DTB_MAX_SIZE 0x3000
#define CFG_DT_ADDR 0x0
/* CFG_EARLY_TA is not set */
#define CFG_EFUSE 1
/* CFG_EFUSE_LAYOUT is not set */
#define CFG_EFUSE_READ_ALL_WRITE_BLOCK 1
#define CFG_EMBED_DTB 1
#define CFG_EMBED_DTB_SOURCE_FILE amlogic-tee.dts
#define CFG_EMBED_PERM_SOURCE_FILE default_perm.txt
/* CFG_ENABLE_SCTLR_RR is not set */
/* CFG_ENABLE_SCTLR_Z is not set */
/* CFG_EXTERNAL_DTB_OVERLAY is not set */
/* CFG_FTRACE_SUPPORT is not set */
#define CFG_FTRACE_US_MS 10000
#define CFG_GENERIC_BOOT 1
/* CFG_GP_SOCKETS is not set */
#define CFG_HDCP 1
/* CFG_HDCP_DEBUG is not set */
#define CFG_HWSUPP_MEM_PERM_PXN 1
#define CFG_HWSUPP_MEM_PERM_WXN 1
/* CFG_HW_KL is not set */
/* CFG_HW_KL_TEST is not set */
#define CFG_HW_RAMDOM_STACK_GUARD 1
#define CFG_KDF_MKL 1
/* CFG_KDF_MKL_MSR is not set */
/* CFG_KDF_MKL_TEST is not set */
#define CFG_KERN_LINKER_ARCH arm
#define CFG_KERN_LINKER_FORMAT elf32-littlearm
#define CFG_KEYMASTER 1
#define CFG_KEYTABLE 1
/* CFG_KEY_DEBUG is not set */
#define CFG_LIBUTILS_WITH_ISOC 1
/* CFG_LOCKDEP is not set */
#define CFG_LOGGER 1
#define CFG_LOG_SHMEM_SIZE 0x00040000
#define CFG_LOG_SHMEM_START (CFG_SHMEM_START + CFG_SHMEM_SIZE - CFG_LOG_SHMEM_SIZE)
#define CFG_LPAE_ADDR_SPACE_SIZE (1ull << 32)
#define CFG_LTC_OPTEE_THREAD 1
#define CFG_MAILBOX 1
#define CFG_MESON_UART 1
#define CFG_MMAP_REGIONS 24
#define CFG_MSG_LONG_PREFIX_MASK 0x1a
#define CFG_NUM_THREADS 16
#define CFG_OPTEE_REVISION_MAJOR 3
#define CFG_OPTEE_REVISION_MINOR 8
#define CFG_OS_REV_REPORTS_GIT_SHA1 1
/* CFG_OTP_LIC is not set */
#define CFG_OTP_SUPPORT 1
/* CFG_PAGED_USER_TA is not set */
#define CFG_PCPK_FROM_MKL 1
#define CFG_PM_STUBS 1
/* CFG_REE_CALLBACK is not set */
#define CFG_REE_FS 1
/* CFG_REE_FS_HASH_VERIFY is not set */
/* CFG_REE_FS_TA is not set */
#define CFG_REE_FS_TA_AML 1
/* CFG_REE_FS_TA_BUFFERED is not set */
/* CFG_REG_DEBUG is not set */
#define CFG_REK_FROM_MKL 1
#define CFG_RESERVED_VASPACE_SIZE (1024 * 1024 * 10)
/* CFG_RNG_API is not set */
#define CFG_RNG_V2 1
#define CFG_RPMB_DRIVER 1
#define CFG_RPMB_FS 1
#define CFG_RPMB_FS_DEV_ID 0
/* CFG_RPMB_FS_FORMAT is not set */
/* CFG_RPMB_WRITE_KEY is not set */
#define CFG_RSV_RAM_SIZE 0x03000000
#define CFG_SCS_INFO 1
#define CFG_SCTLR_ALIGNMENT_CHECK 1
/* CFG_SECSTOR_TA is not set */
/* CFG_SECSTOR_TA_MGMT_PTA is not set */
#define CFG_SECURE_CRYPTO_THREAD 3
/* CFG_SECURE_DATA_PATH is not set */
/* CFG_SECURE_TIME_SOURCE_REE is not set */
#define CFG_SECURE_TIME_SOURCE_TEE 1
#define CFG_SHMEM_SIZE 0x00800000
#define CFG_SHMEM_START (CFG_TZDRAM_START + CFG_RSV_RAM_SIZE - CFG_SHMEM_SIZE)
/* CFG_SHM_MMAP_API is not set */
/* CFG_SHOW_CONF_ON_BOOT is not set */
#define CFG_SM_NO_CYCLE_COUNTING 1
/* CFG_SYSCALL_FTRACE is not set */
/* CFG_SYSCALL_WRAPPERS_MCOUNT is not set */
#define CFG_SYSTEM_PTA 1
#define CFG_S_STORAGE 1
#define CFG_TA_ANTIROLLBACK 1
/* CFG_TA_ANTIROLLBACK_DEBUG is not set */
#define CFG_TA_ANTIROLLBACK_SW 1
#define CFG_TA_ASLR 1
#define CFG_TA_ASLR_MAX_OFFSET_PAGES 128
#define CFG_TA_ASLR_MIN_OFFSET_PAGES 0
#define CFG_TA_BIGNUM_MAX_BITS 4096
#define CFG_TA_DYNLINK 1
#define CFG_TA_FLOAT_SUPPORT 1
/* CFG_TA_GPROF_SUPPORT is not set */
/* CFG_TA_MARKETID is not set */
#define CFG_TA_MBEDTLS 1
#define CFG_TA_MBEDTLS_MPI 1
/* CFG_TA_MBEDTLS_SELF_TEST is not set */
/* CFG_TA_MUTEX is not set */
#define CFG_TEE_API_VERSION GPD-1.1-dev
#define CFG_TEE_CORE_DEBUG 1
/* CFG_TEE_CORE_EMBED_INTERNAL_TESTS is not set */
#define CFG_TEE_CORE_LOG_LEVEL 2
/* CFG_TEE_CORE_MALLOC_DEBUG is not set */
#define CFG_TEE_CORE_NB_CORE 8
#define CFG_TEE_CORE_TA_TRACE 1
#define CFG_TEE_FW_IMPL_VERSION FW_IMPL_UNDEF
#define CFG_TEE_FW_MANUFACTURER FW_MAN_UNDEF
#define CFG_TEE_IMPL_DESCR OPTEE
#define CFG_TEE_MANUFACTURER LINARO
#define CFG_TEE_RAM_VA_SIZE 0x00100000
#define CFG_TEE_TA_LOG_LEVEL 1
/* CFG_TEE_TA_MALLOC_DEBUG is not set */
#define CFG_TEE_TIMER 1
#define CFG_TVP 1
#define CFG_TVP_RAM_SIZE 0x01000000
#define CFG_TVP_RAM_START (CFG_SHMEM_START - CFG_TVP_RAM_SIZE)
#define CFG_TZDRAM_SIZE (CFG_VIDFW_RAM_START - CFG_TZDRAM_START)
#define CFG_TZDRAM_START 0x05300000
/* CFG_ULIBS_MCOUNT is not set */
/* CFG_ULIBS_SHARED is not set */
#define CFG_UNIFY_KEY 1
#define CFG_UNWIND 1
#define CFG_VENDOR_PROPS 1
#define CFG_VIDEO_FW_LOAD 1
#define CFG_VIDFW_RAM_SIZE 0x00100000
#define CFG_VIDFW_RAM_START (CFG_TVP_RAM_START - CFG_VIDFW_RAM_SIZE)
/* CFG_VIRTUALIZATION is not set */
/* CFG_WATERMARK_NEXGUARD is not set */
/* CFG_WATERMARK_VERIMATRIX is not set */
#define CFG_WERROR 1
#define CFG_WITH_ARM_TRUSTED_FW 1
#define CFG_WITH_DEBUG 1
/* CFG_WITH_PAGER is not set */
#define CFG_WITH_SOFTWARE_PRNG 1
#define CFG_WITH_STACK_CANARIES 1
#define CFG_WITH_STATS 1
#define CFG_WITH_STEST 1
#define CFG_WITH_USER_TA 1
#define CFG_WITH_VFP 1
#define PLATFORM_FLAVOR sc2
#define PLATFORM_FLAVOR_sc2 1
#define PLATFORM_meson 1
#define _CFG_CORE_LTC_ACIPHER 1
#define _CFG_CORE_LTC_AES 1
/* _CFG_CORE_LTC_AES_ARM32_CE is not set */
/* _CFG_CORE_LTC_AES_ARM64_CE is not set */
#define _CFG_CORE_LTC_ASN1 1
#define _CFG_CORE_LTC_AUTHENC 1
#define _CFG_CORE_LTC_BIGNUM_MAX_BITS 4096
#define _CFG_CORE_LTC_CBC 1
#define _CFG_CORE_LTC_CBC_MAC 1
#define _CFG_CORE_LTC_CCM 1
/* _CFG_CORE_LTC_CE is not set */
#define _CFG_CORE_LTC_CIPHER 1
#define _CFG_CORE_LTC_CMAC 1
#define _CFG_CORE_LTC_CTR 1
#define _CFG_CORE_LTC_CTS 1
#define _CFG_CORE_LTC_DES 1
#define _CFG_CORE_LTC_DH 1
#define _CFG_CORE_LTC_DSA 1
#define _CFG_CORE_LTC_ECB 1
#define _CFG_CORE_LTC_ECC 1
#define _CFG_CORE_LTC_HASH 1
#define _CFG_CORE_LTC_HMAC 1
/* _CFG_CORE_LTC_HWSUPP_PMULL is not set */
#define _CFG_CORE_LTC_MAC 1
#define _CFG_CORE_LTC_MD5 1
#define _CFG_CORE_LTC_MPI 1
#define _CFG_CORE_LTC_OPTEE_THREAD 1
/* _CFG_CORE_LTC_PAGER is not set */
#define _CFG_CORE_LTC_RSA 1
#define _CFG_CORE_LTC_SHA1 1
/* _CFG_CORE_LTC_SHA1_ARM32_CE is not set */
/* _CFG_CORE_LTC_SHA1_ARM64_CE is not set */
#define _CFG_CORE_LTC_SHA224 1
#define _CFG_CORE_LTC_SHA256 1
/* _CFG_CORE_LTC_SHA256_ARM32_CE is not set */
/* _CFG_CORE_LTC_SHA256_ARM64_CE is not set */
#define _CFG_CORE_LTC_SHA384 1
#define _CFG_CORE_LTC_SHA512 1
#define _CFG_CORE_LTC_SHA512_256 1
#define _CFG_CORE_LTC_SIZE_OPTIMIZATION 1
#define _CFG_CORE_LTC_SM2_DSA 1
#define _CFG_CORE_LTC_SM2_KEP 1
#define _CFG_CORE_LTC_SM2_PKE 1
#define _CFG_CORE_LTC_VFP 1
#define _CFG_CORE_LTC_XTS 1
#endif
