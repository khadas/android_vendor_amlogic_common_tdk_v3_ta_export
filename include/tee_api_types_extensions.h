/*
 * Copyright (C) 2015 Amlogic, Inc. All rights reserved.
 *
 * All information contained herein is Amlogic confidential.
 *
 * This software is provided to you pursuant to Software License
 * Agreement (SLA) with Amlogic Inc ("Amlogic"). This software may be
 * used only in accordance with the terms of this agreement.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification is strictly prohibited without prior written permission
 * from Amlogic.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef TEE_API_TYPES_EXTENSIONS_H
#define TEE_API_TYPES_EXTENSIONS_H

#include <types_ext.h>
#include <sys/queue.h>

#define TEE_ERROR_TA_VERSION                               0x7FFFFFFF
#define TEE_ERROR_ARB_TABLE_NO_SPACE                       0x7FFFFFFE
#define TEE_ERROR_RPMB_AUTH_KEY_PROGRAMMED                 0x7FFFFFFD

struct tee_video_fw_info {
	uint32_t type;
	uint32_t offset;
	uint32_t size;
};

typedef void *TEE_Tvp_Handle;
#define TEE_TVP_POOL_MAX_COUNT          4

#define TEE_TVP_VIDEO_LAYER_OFFSET      0
#define TEE_TVP_VIDEO_TYPE_OFFSET       4
#define TEE_TVP_MEM_LEVEL_OFFSET        8
#define TEE_TVP_VIDEO_LAYER_MASK        0xF
#define TEE_TVP_VIDEO_TYPE_MASK         0xF0
#define TEE_TVP_MEM_LEVEL_MASK          0xF00

#define TEE_TVP_CFG_VIDEO_LAYER_NONE    (0<<TEE_TVP_VIDEO_LAYER_OFFSET)
#define TEE_TVP_CFG_VIDEO_LAYER_1       (1<<TEE_TVP_VIDEO_LAYER_OFFSET)
#define TEE_TVP_CFG_VIDEO_LAYER_2       (2<<TEE_TVP_VIDEO_LAYER_OFFSET)
#define TEE_TVP_CFG_DRM_PLAYBACK        (1<<TEE_TVP_VIDEO_TYPE_OFFSET)
#define TEE_TVP_CFG_CAS_LIVE            (2<<TEE_TVP_VIDEO_TYPE_OFFSET)
#define TEE_TVP_CFG_CAS_RECORD          (3<<TEE_TVP_VIDEO_TYPE_OFFSET)
#define TEE_TVP_CFG_CAS_PLAYBACK        (4<<TEE_TVP_VIDEO_TYPE_OFFSET)

typedef struct {
	paddr_t pa;
	size_t size;
} tee_vdec_info_t;

typedef struct {
	uint32_t cfg;
	tee_vdec_info_t input;
	tee_vdec_info_t output[TEE_TVP_POOL_MAX_COUNT];
} tvp_channel_cfg_t;

/* Compatible to previous definition */
typedef tee_vdec_info_t vdec_info_t;

#define TEE_SECURE_TIMER_FLAG_ONESHOT   0
#define TEE_SECURE_TIMER_FLAG_PERIOD    1
typedef void *TEE_TimerHandle;
typedef void (*tee_timer_cb_t)(void *args);

struct tee_timer {
	tee_timer_cb_t cb;
	void *args;
	uint32_t timeout;
	uint32_t flags;
	TAILQ_ENTRY(tee_timer) link;
};

/* key user */
#define KT_USER_M2M_0        (0)
#define KT_USER_M2M_1        (1)
#define KT_USER_M2M_2        (2)
#define KT_USER_M2M_3        (3)
#define KT_USER_M2M_4        (4)
#define KT_USER_M2M_5        (5)
#define KT_USER_TSD          (8)
#define KT_USER_TSN          (9)
#define KT_USER_TSE          (10)

/* key algorithm */
#define KT_ALGO_AES          (0)
#define KT_ALGO_TDES         (1)
#define KT_ALGO_DES          (2)
#define KT_USAGE_S17         (3)
#define KT_ALGO_NDL          (7)
#define KT_ALGO_ND           (8)
#define KT_ALGO_CSA3         (9)
#define KT_ALGO_CSA2         (10)
#define KT_ALGO_HMAC         (13)

/* key flag */
#define KT_FLAG_NONE         (0)
#define KT_FLAG_ENC_ONLY     (1)
#define KT_FLAG_DEC_ONLY     (2)
#define KT_FLAG_ENC_DEC      (3)

/* key level */
#define KT_LEVEL_0           (0)
#define KT_LEVEL_1           (1)
#define KT_LEVEL_2           (2)
#define KT_LEVEL_3           (3)
#define KT_LEVEL_4           (4)
#define KT_LEVEL_5           (5)
#define KT_LEVEL_6           (6)
#define KT_LEVEL_7           (7)

/* key TEE private */
#define KT_TEE_ONLY          (1)
#define KT_REE_ONLY          (0)

/* key source */
#define KT_SRC_TEE_CERT     (16)
#define KT_SRC_REE_CERT     (15)
#define KT_SRC_NSK          (14)
#define KT_SRC_MSR3         (13)
#define KT_SRC_VO           (12)
#define KT_SRC_SPKL         (11)
#define KT_SRC_SPHOST       (10)
#define KT_SRC_TEEKL_MSR2   (9)
#define KT_SRC_TEEKL_ETSI   (8)
#define KT_SRC_TEEKL_NAGRA  (7)
#define KT_SRC_TEEKL_AML    (6)
#define KT_SRC_TEE_HOST     (5)
#define KT_SRC_REEKL_MSR2   (4)
#define KT_SRC_REEKL_ETSI   (3)
#define KT_SRC_REEKL_NAGRA  (2)
#define KT_SRC_REEKL_AML    (1)
#define KT_SRC_REE_HOST     (0)

#define KT_ALLOC_FLAG_IV_MASK         (1 << 0)
#define KT_ALLOC_FLAG_HOST_MASK       (1 << 1)
#define KT_ALLOC_FLAG_NSK_M2M_MASK    (1 << 8)

#define CRYPTO_DMA_THREAD_DEFAULT     0xffffffff
/* keyladder narga mode mrk type */
#define TEE_KL_MRK_NAGRA_NSD    (0)
#define TEE_KL_MRK_ORK_REE      (1)
#define TEE_KL_MRK_ORK_TEE      (2)
#define TEE_KL_MRK_NAGRA        (3)

typedef struct tee_key_cfg_s {
	uint32_t key_userid;
	uint32_t key_algo;
	uint32_t key_flag;
	uint32_t key_level;
	uint32_t tee_priv;
	uint32_t key_source;
}tee_key_cfg_t;

typedef enum {
	TEE_KL_MODE_MKL,
	TEE_KL_MODE_NAGRA,
	TEE_KL_MODE_ETSI,
	TEE_KL_MODE_CSA2,
	TEE_KL_MODE_MAX,
} tee_kl_mode_t;

typedef enum {
	TEE_KL_ALGO_TDES = 0,
	TEE_KL_ALGO_AES = 1,
	TEE_KL_ALGO_MAX,
} tee_kl_algo_t;

typedef struct {
	uint32_t crypto;                  /* Key table crypto flag */
	uint32_t algo;                    /* Key table algorithm */
	uint32_t uid;                     /* Key table user ID */
} tee_kl_usage_t;

typedef struct tee_kl_run_param_v2 {
	uint32_t        kt_handle;        /* Key table handle */
	uint8_t         levels;           /* Key ladder level, levle can be 3 ~ 6, should map EFUSE defintion */
	uint8_t         secure_level;     /* Key ladder secure level, should be 0 ~ 3 */
	tee_kl_usage_t  usage;            /* Key ladder usage rule */
	uint8_t         module_id;        /* Key ladder module ID */
	tee_kl_algo_t   kl_algo;          /* Key ladder algo, *NOT* root key algo */
	uint8_t         mrk_cfg_index;    /* MRK config index, 0 ~ 3, should map EFUSE defintion */
	uint8_t         eks[6][16];       /* eks[0] is ECW, eks[n] is EKn, n is 1 ~ 5 */
} tee_kl_run_conf_t;

typedef struct tee_kl_run_param_nv {
	uint32_t        kt_handle;        /* Key table handle */
	uint8_t         levels;           /* Key ladder level, levle can be 3 ~ 6, should map EFUSE defintion */
	uint8_t         secure_level;     /* Key ladder secure level, should be 0 ~ 3 */
	uint8_t         tee_priv;         /* Key ladder tee private flag, should be 0 or 1 */
	uint8_t         reserved0;        /* for 32 bits aligned */
	tee_kl_usage_t  usage;            /* Key ladder usage rule */
	tee_kl_algo_t   kl_algo;          /* Key ladder algo, *NOT* root key algo */
	tee_kl_mode_t   kl_mode;          /* Key ladder mode, 0:MKL/1:Nagra/2:ETSI/3:CAS2 */
	uint8_t         module_id;        /* Key ladder module ID */
	uint8_t         mrk_cfg_index;    /* MRK config index, 0 ~ 3, should map EFUSE defintion */
	uint8_t         func_id;          /* func id, 0 ~ 3 */
	uint8_t         reserved1;        /* for 32 bits aligned */
	uint8_t         eks[6][16];       /* eks[0] is ECW, eks[n] is EKn, n is 1 ~ 5 */
} tee_kl_run_conf_nv_t;

typedef struct tee_kl_cr_conf {
	uint8_t         module_id;        /* Key ladder module ID */
	tee_kl_algo_t   kl_algo;          /* Key ladder algo, *NOT* root key algo */
	uint8_t         mrk_cfg_index;    /* MRK config index should map EFUSE defintion */
	uint8_t         ek[16];           /* CR EK value, If is 3 level KL, ek should be EK2 */
	uint8_t         nonce[16];        /* CR nonce value */
} tee_kl_cr_conf_t;

typedef void* TNgwmEmbedder;

/*
  @brief
  Result returned by NexGuard watermark HAL interface functions.
*/
typedef enum {
	NGWM_HAL_SUCCESS,
	NGWM_HAL_ERROR,
	NGWM_HAL_LAST_STATUS //Not used
} TNgwmHalResult;

/*
  @ingroup g_wm_hal
  @brief
  This structure defines the NexGuard watermark HAL interface content.
  @details
  It is a collection of function pointers composing the interface.
*/
typedef struct {
	/*
	   @brief
	   NexGuard watermark HAL interface version number.
	   @details
	   Assign it to the ::NGWMHALAPI_VERSION_INT result.
	*/
	uint32_t version;

	/*
	   @brief
	   Set the seed to be used for watermarking

	   @param[in] pxEmbedder
	   Embedder object handle related to IP core to be configured

	   @param[in] xSeed
	   Seed to be to configure in the hardware embedder

	   @retval ::NGWM_HAL_SUCCESS
	   The operation completed successfully

	   @retval ::NGWM_HAL_ERROR
	   The operation failed
	*/
	TNgwmHalResult (*setSeed)(TNgwmEmbedder pxEmbedder, uint32_t xSeed);

	/*
	   @brief
	   Set the operator ID to be used for watermarking

	   @param[in] pxEmbedder
	   Embedder object handle related to IP core to be configured

	   @param[in] xOperatorId
	   Operator ID to configure in the hardware embedder

	   @retval ::NGWM_HAL_SUCCESS
	   The operation completed successfully

	   @retval ::NGWM_HAL_ERROR
	   The operation failed
	*/
	TNgwmHalResult (*setOperatorId)(TNgwmEmbedder pxEmbedder, uint8_t xOperatorId);

	/*
	   @brief
	   Set the settings to be used for watermarking

	   Data in pxSettings parameter is encapsulated in a TLV descriptor
	   complying with the format below and is actually conveying an array
	   of settings for potentially several output types.

	   @code
	   tag                   8 uimsbf  h44
	   length                8 uimsbf
	   technology_type       8 uimsbf
	   technology_version   16 uimsbf
	   settings_nb           8 uimsbf
	   for(i=0; i<N; i++) {
		setting_type        8 uimsbf
		setting_data     21*8 uimsbf
	   }

	   @endcode
	   Settings conveyed in the array, and also the number of entries in
	   the array, are SoC specific and depend on the IP core integration
	   model.If the SoC is able to configure IP cores depending on the type
	   of output (e.g. SDR8, HDR10, etc), the settings array contains an
	   entry for each supported output type. Otherwise, the settings array
	   contains one single entry applicable to any output.

	   @param[in] pxEmbedder
	   Embedder object handle related to IP core to be configured

	   @param[in] pxSettings
	   Buffer containing the settings to configure in the hardware embedder.

	   @param[in] xSize
	   Size in bytes of the pxSettings array

	   @retval ::NGWM_HAL_SUCCESS
	   The operation completed successfully

	   @retval ::NGWM_HAL_ERROR
	   The operation failed
	*/
	TNgwmHalResult (*setSettings)(TNgwmEmbedder pxEmbedder, const uint8_t* pxSettings, uint32_t xSize);

	/*
	   @brief
	   Set the device ID to be used for watermarking

	   @param[in] pxEmbedder
	   Embedder object handle related to IP core to be configured

	   @param[in] pxDeviceId
	   Device ID to configure in the hardware embedder

	   @param[in] xSizeInBits
	   Size in bits of the device ID (e.g. typically 32 bits)

	   @retval ::NGWM_HAL_SUCCESS
	   The operation completed successfully

	   @retval ::NGWM_HAL_ERROR
	   The operation failed
	*/
	TNgwmHalResult (*setDeviceId)(TNgwmEmbedder pxEmbedder, const uint8_t* pxDeviceId, uint8_t xSizeInBits);

	/*
	   @brief
	   Set the timecode to be used for watermarking.

	   The value of the timecode provided to this function is already a
	   16-bit value using a 15-minute resolution over a year.

	   @param[in] pxEmbedder
	   Embedder object handle related to IP core to be configured

	   @param[in] xTimeCode
	   Timecode to configure in the hardware embedder

	   @retval ::NGWM_HAL_SUCCESS
	   The operation completed successfully

	   @retval ::NGWM_HAL_ERROR
	   The operation failed
	*/
	TNgwmHalResult (*setTimeCode)(TNgwmEmbedder pxEmbedder, uint16_t xTimeCode);

	/*
	   @brief
	   Activate/deactivate watermark embedding.

	   @param[in] pxEmbedder
	   Embedder object handle related to IP core to be configured

	   @param[in] xIsEnabled
	   When this boolean is set to TRUE, watermark embedding is activated.
	   Otherwise it is deactivated.

	   @retval ::NGWM_HAL_SUCCESS
	   The operation completed successfully

	   @retval ::NGWM_HAL_ERROR
	   The operation failed
	*/
	TNgwmHalResult (*enableService)(TNgwmEmbedder pxEmbedder, bool xIsEnabled);

	/*
	   @brief
	   Enables or disables the stub debug test pattern.

	   The stub pattern is a visible mark used for test purposes. It is
	   easier to check the integration when embedding a stub pattern than
	   using the real imperceptible watermark.

	   Note that the stub is only visible when the watermark embedding
	   is turned on.

	   @param[in] pxEmbedder
	   Embedder object handle related to IP core to be configured

	   @param[in] xIsEnabled
	   When this boolean is set to TRUE, the stub test pattern is activated.
	   Otherwise it is deactivated.

	   @retval ::NGWM_HAL_SUCCESS
	   The operation completed successfully

	   @retval ::NGWM_HAL_ERROR
	   The operation failed
	*/
	TNgwmHalResult (*setStubEmbedding)(TNgwmEmbedder pxEmbedder, bool xIsEnabled);

	/*
	   @brief
	   Enables or disables the 24-bit payload mode.

	   By default, the 24-bit payload mode is disabled and the IP core
	   works in 56-bit payload mode.

	   @param[in] pxEmbedder
	   Embedder object handle related to IP core to be configured

	   @param[in] xIsEnabled
	   When this boolean is set to TRUE, the 24-bit payload mode is enabled.
	   Otherwise it is disabled and the IP core works in 56-bit mode.

	   @retval ::NGWM_HAL_SUCCESS
	   The operation completed successfully

	   @retval ::NGWM_HAL_ERROR
	   The operation failed
	*/
	TNgwmHalResult (*set24bitMode)(TNgwmEmbedder pxEmbedder, bool xIsEnabled);

	/**<
	  @brief
	  Allocates @c xSize bytes of memory.

	  @param[in]      xSize
	  Number of bytes to allocate

	  @return
	  Returns a pointer to the allocated buffer when the operation succeeds.
	  Returns @c NULL otherwise.
	 */
	void* (*allocate)(size_t xSize);

	/**<
	  @brief
	  Frees the allocated memory referenced by @c pxMem.

	  @param[in]      pxMem
	  A pointer to the memory to be freed.
	 */
	void (*free)(void* pxMem);

	/**<
	  @brief
	  This function logs a NULL-terminated string message.

	  @param[in] pxMessage
	  Null-terminated message string to be logged.
	 */
	void (*log)(const char* pxMessage);

	/**<
	  @brief
	  Get the state of nexguard watermark service.

	  @param[in] pxEmbedder
	  Embedder object handle related to IP core to be configured

	  @param[in] state
	  Point to the state variable

	  @retval ::NGWM_HAL_SUCCESS
	  The operation completed successfully

	  @retval ::NGWM_HAL_ERROR
	  The operation failed
	*/
	TNgwmHalResult (*getState)(TNgwmEmbedder pxEmbedder, uint32_t* state);
} INgwmHal;

typedef enum VM_HW_Err {
	VM_HW_OK = 0,
	VM_HW_PARAM_ERROR,
	VM_HW_FAIL,
} VM_HW_Err_t;

// Verimatrix WaterMark Core Parameters
typedef struct {
//versioning
	uint8_t		version_major;
	uint8_t		version_minor;
//embedding part
	uint8_t		watermark_on;
	uint8_t		freq_distance[3][3];
	uint8_t		background_embedding_on;
	uint16_t	embedding_strength_threshold_8[3];
	uint16_t	embedding_strength_threshold_bg_8[3];
	uint16_t	embedding_strength_threshold_10[12];
	uint16_t	embedding_strength_threshold_bg_10[12];
	uint16_t	embedding_strength_threshold_12[48];
	uint16_t	embedding_strength_threshold_bg_12[48];
	uint16_t	direction_max;
	int8_t		strength_multiply;
//rendering part
	uint8_t		payload_symbols[1920];
	uint8_t		symbols_rows;
	uint8_t		symbols_cols;
	uint8_t		symbols_xpos;
	uint8_t		symbols_ypos;
	uint8_t		symbol_size;
	uint16_t	spacing_vert;
	uint16_t	spacing_horz;
	uint8_t		symbol_scale_control;
} vmx_hw_soc_rend_t;

/* nagra type */
typedef void *TEE_Nagra_Cert_Handle;

typedef enum {
	TEE_CERT_TIMEOUT_DEFAULT,
	TEE_CERT_TIMEOUT_OTP,
	TEE_LAST_CERT_TIMEOUT
} timeout_type_t;

typedef struct {
	uint8_t input_data[32];
	uint8_t output_data[32];
	uint8_t status[4];
	uint8_t cmd[4];
	timeout_type_t timeout;
} cert_command_t;

typedef enum {
	TEE_CAS_ID_AML,
	TEE_CAS_ID_ACGK,
	TEE_CAS_ID_DVGK,
	TEE_CAS_ID_DVUK,
	TEE_CAS_ID_DGPK,
	TEE_CAS_ID_SECPU,
	TEE_CAS_ID_ETSI_0_1_2,
	TEE_CAS_ID_ETSI_3,
	TEE_CAS_ID_MSR,
	TEE_CAS_ID_VO,
	TEE_CAS_ID_NUID,
	TEE_CAS_ID_CONAX,
	TEE_CAS_ID_NSK,

	TEE_CAS_ID_MAX,
} cas_id_t;

typedef enum {
	TEE_NSK_MEM_TYPE_MEM,
	TEE_NSK_MEM_TYPE_SECURE_TOP,
	TEE_NSK_MEM_TYPE_MAX,
} nsk_mem_type_t;

#endif
