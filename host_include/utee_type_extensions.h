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

#ifndef UTEE_TYPE_EXTENSIONS_H
#define UTEE_TYPE_EXTENSIONS_H

#include <tee_api_types.h>
#include <tee_api_types_extensions.h>
#include <utee_defines.h>

/* ================================ MISC ================================ */

/* ================================ EFUSE ================================ */
#define TEE_EXTEND_EFUSE_READ_TEE                          0x1000
#define TEE_EXTEND_EFUSE_READ_REE                          0x1001
#define TEE_EXTEND_EFUSE_READ                              0x1002
#define TEE_EXTEND_EFUSE_WRITE_BLOCK                       0x1003

struct tee_efuse_read_tee_param {
	uint8_t *buf;
	uint32_t offset;
	size_t size;
};

struct tee_efuse_read_user_param {
	uint8_t *buf;
	uint32_t offset;
	size_t size;
};

struct tee_efuse_read_param {
	uint8_t *buf;
	uint32_t offset;
	size_t size;
};

struct tee_efuse_write_block_param {
	uint8_t *buf;
	uint32_t block;
};

/* =============================== UNIFYKEY =============================== */
#define TEE_EXTEND_UNIFY_READ                              0x1010

struct tee_unify_read_param {
	uint8_t *name;
	uint32_t namelen;
	uint8_t *buf;
	uint32_t buflen;
	uint32_t readlen;
};

/* ================================ HDCP ================================ */
#define TEE_EXTEND_HDCP_GET_STATE                          0x1020
#define TEE_EXTEND_HDCP_LOAD_KEY                           0x1021
#define TEE_EXTEND_HDCP_SET_STREAMID                       0x1022
#define TEE_EXTEND_HDCP_GET_STREAMID                       0x1023
#define TEE_EXTEND_HDMI_GET_STATE                          0x1024

struct tee_hdcp_get_state_param {
	uint32_t mode;
	uint32_t auth;
};

struct tee_hdcp_load_key_param {
	uint32_t type;
	uint8_t *keybuf;
	uint32_t keylen;
};

struct tee_hdcp_streamid_param {
	uint32_t type;
};

struct tee_hdmi_get_state_param {
	uint32_t state;
	uint32_t reserved;
};

/* ================================ VIDEO ================================ */
#define TEE_EXTEND_VIDEO_LOAD_FW                           0x1030

struct tee_video_fw_param {
	void *firmware;
	uint32_t fw_size;
	void *info;
	uint32_t info_size;
};

/* ================================ TVP ================================ */
#define TEE_EXTEND_VDEC_GET_INFO                           0x1040
#define TEE_EXTEND_TVP_OPEN_CHAN                           0x1041
#define TEE_EXTEND_TVP_CLOSE_CHAN                          0x1042
#define TEE_EXTEND_TVP_BIND_CHAN                           0x1043
#define TEE_EXTEND_VDEC_MMAP                               0x1044
#define TEE_EXTEND_VDEC_MMAP_CACHED                        0x1045
#define TEE_EXTEND_VDEC_MUNMAP                             0x1046
#define TEE_EXTEND_TVP_GET_VIDEO_SIZE                      0x1047
#define TEE_EXTEND_TVP_GET_DISPLAY_SIZE                    0x1048
#define TEE_EXTEND_TVP_SET_VIDEO_LAYER                     0x1049
#define TEE_EXTEND_TVP_GET_VIDEO_LAYER                     0x104a
#define TEE_EXTEND_TVP_SET_AUDIO_MUTE                      0x104b

struct tee_vdec_info_param {
	paddr_t pa;
	size_t size;
};

struct tee_tvp_open_chan_param {
	uint32_t cfg;
	tee_vdec_info_t input;
	tee_vdec_info_t output[TEE_TVP_POOL_MAX_COUNT];
	TEE_Tvp_Handle handle;
};

struct tee_tvp_close_chan_param {
	TEE_Tvp_Handle handle;
};

struct tee_tvp_bind_chan_param {
	TEE_Tvp_Handle handle;
	TEE_UUID uuid;
};

struct tee_vdec_mmap_param {
	paddr_t pa;
	size_t size;
	vaddr_t va;
};

struct tee_vdec_munmap_param {
	paddr_t pa;
	size_t size;
};

struct tee_tvp_resolution_param {
	uint32_t width;
	uint32_t height;
};

struct tee_tvp_video_layer_param {
	uint32_t video_layer;
	uint32_t enable;
	uint32_t flags;
};

struct tee_tvp_audio_mute_param {
	uint32_t mute;
};

/* ================================ KEYMASTER ================================ */
#define TEE_EXTEND_KM_SET_BOOT_PARAMS                      0x1050
#define TEE_EXTEND_KM_GET_BOOT_PARAMS                      0x1051

struct tee_km_boot_params {
	uint32_t device_locked;
	uint32_t verified_boot_state;
	uint8_t verified_boot_key[TEE_SHA256_HASH_SIZE];
	uint8_t verified_boot_hash[TEE_SHA256_HASH_SIZE];
};

/* ================================ DESC ================================ */
#define TEE_EXTEND_DESC_INIT                               0x1070
#define TEE_EXTEND_DESC_ALLOC_CHANNEL                      0x1071
#define TEE_EXTEND_DESC_SET_ALGO                           0x1072
#define TEE_EXTEND_DESC_SET_MODE                           0x1073
#define TEE_EXTEND_DESC_SET_PID                            0x1074
#define TEE_EXTEND_DESC_SET_KEY                            0x1075
#define TEE_EXTEND_DESC_SET_OUTPUT                         0x1076
#define TEE_EXTEND_DESC_FREE_CHANNEL                       0x1077
#define TEE_EXTEND_DESC_RESET                              0x1078
#define TEE_EXTEND_DESC_EXIT                               0x1079

struct tee_desc_alloc_channel_param {
	int dsc_no;
	int fd;
};

struct tee_desc_free_channel_param {
	int dsc_no;
	int fd;
};

struct tee_desc_reset_param {
	int dsc_no;
	int all;
};

struct tee_desc_set_algo_param {
	int dsc_no;
	int fd;
	int algo;
};

struct tee_desc_set_mode_param {
	int dsc_no;
	int fd;
	int mode;
};

struct tee_desc_set_pid_param {
	int dsc_no;
	int fd;
	int pid;
};

struct tee_desc_set_key_param {
	int dsc_no;
	int fd;
	int parity;
	unsigned char *key;
	uint32_t key_type;
};

struct tee_desc_set_output_param {
	int module;
	int output;
};

struct tee_desc_dvr_info_param {
	uint8_t svc_idx;
	uint8_t pid_count;
	uint16_t pids[8];
};

/* ================================ TIMER ================================ */
#define TEE_EXTEND_TIMER_CREATE                            0x1080
#define TEE_EXTEND_TIMER_DESTROY                           0x1081

struct tee_timer_param {
	uint32_t handle;
	uint32_t timeout;
	uint32_t flags;
};

/* ================================ PROVISION ============================ */
#define TEE_EXTEND_CIPHER_ENCRYPT_WITH_KWRAP               0x1090
#define TEE_EXTEND_CIPHER_DECRYPT_WITH_KWRAP               0x1091
#define TEE_EXTEND_AE_DECRYPT_WITH_DERIVED_KWRAP           0x1092
#define TEE_EXTEND_AE_DECRYPT_WITH_DERIVED_KSECRET         0x1093

struct tee_cipher_encrypt_with_kwrap_param {
	const uint8_t *iv;
	uint32_t iv_len;
	const uint8_t *src;
	uint32_t src_len;
	uint8_t *dst;
	uint32_t *dst_len;
};

struct tee_cipher_decrypt_with_kwrap_param {
	const uint8_t *iv;
	uint32_t iv_len;
	const uint8_t *src;
	uint32_t src_len;
	uint8_t *dst;
	uint32_t *dst_len;
};

struct tee_ae_crypt_with_derived_kwrap_param {
	uint32_t algo;
	uint8_t *iv;
	uint32_t ivlen;
	uint8_t *src;
	uint32_t srclen;
	uint8_t *dst;
	uint32_t dstlen;
	uint8_t *tag;
	uint32_t taglen;
};

struct tee_ae_crypt_with_derived_ksecret_param {
	uint32_t algo;
	uint8_t *iv;
	uint32_t ivlen;
	uint8_t *src;
	uint32_t srclen;
	uint8_t *dst;
	uint32_t dstlen;
	uint8_t *tag;
	uint32_t taglen;
};

/* ================================ KEYTABLE ================================ */
#define TEE_EXTEND_KT_ALLOC                                0x1060
#define TEE_EXTEND_KT_SET_KEY                              0x1061
#define TEE_EXTEND_KT_FREE                                 0x1062
#define TEE_EXTEND_KT_CONFIG                               0x1063
#define TEE_EXTEND_KT_CRYPTO                               0x1064
#define TEE_EXTEND_KT_GET_STATUS                           0x1065

struct tee_kt_alloc_param {
	uint32_t flag;
	uint32_t handle;
};

struct tee_kt_config_param {
	uint32_t handle;
	tee_key_cfg_t key_cfg;
};

struct tee_kt_set_key_param {
	uint32_t handle;
	uint8_t *key;
	uint32_t keylen;
};

struct tee_kt_get_status_param {
	uint32_t handle;
	uint32_t *status;
};

struct tee_kt_free_param {
	uint32_t handle;
};

struct tee_kt_crypto_param {
	uint32_t handle;
	uint32_t algo;
	const uint8_t *iv;
	uint32_t iv_len;
	const uint8_t *src;
	uint32_t src_len;
	uint8_t *dst;
	uint32_t dst_len;
	uint32_t decrypt;
	uint32_t thread;
};

/* ================================ KEYLADDER ============================ */
#define TEE_EXTEND_KL_RUN_V2                                0x10A0
#define TEE_EXTEND_KL_CR_V2                                 0x10A1
#define TEE_EXTEND_KL_RUN_NV                                0x10A2

struct tee_kl_cr_param_v2 {
	struct tee_kl_cr_conf cfg;
	uint8_t dnonce[16];
};

/* =========================== VX WATERMARK ============================= */
#define TEE_EXTEND_VXWM_SET_PARA_REND                      0x10B0
#define TEE_EXTEND_VXWM_SET_PARA_LAST                      0x10B1

typedef struct {
	void *para;
	uint32_t para_len;
	uint8_t svc_idx;
} tee_vxwm_param;

/* =========================== NG WATERMARK ============================= */
#define TEE_EXTEND_NGWM_SET_SEED                           0x10C0
#define TEE_EXTEND_NGWM_SET_OPERATOR_ID                    0x10C1
#define TEE_EXTEND_NGWM_SET_SETTINGS                       0x10C2
#define TEE_EXTEND_NGWM_SET_DEVICE_ID                      0x10C3
#define TEE_EXTEND_NGWM_SET_TIME_CODE                      0x10C4
#define TEE_EXTEND_NGWM_ENABLE_SERVICE                     0x10C5
#define TEE_EXTEND_NGWM_SET_STUB_EMBEDDING                 0x10C6
#define TEE_EXTEND_NGWM_SET_24BIT_MODE                     0x10C7

typedef struct {
	void *pxEmbedder;
	uint32_t xSeed;
} ngwm_set_seed_param;

typedef struct {
	void *pxEmbedder;
	uint8_t xOperatorId;
} ngwm_set_operatorid_param;

typedef struct {
	void *pxEmbedder;
	const uint8_t *pxSettings;
	uint32_t xSize;
} ngwm_set_settings_param;

typedef struct {
	void *pxEmbedder;
	const uint8_t *pxDeviceId;
	uint8_t xSizeInBits;
} ngwm_set_deviceid_param;

typedef struct {
	void *pxEmbedder;
	uint16_t xTimeCode;
} ngwm_set_time_code_param;

typedef struct {
	void *pxEmbedder;
	bool xIsEnabled;
} ngwm_enable_service_param;

typedef struct {
	void *pxEmbedder;
	bool xIsEnabled;
} ngwm_set_stub_embedding_param;

typedef struct {
	void *pxEmbedder;
	bool xIsEnabled;
} ngwm_set_24bit_mode_param;


/* =========================== CALLBACK ============================= */
#define TEE_EXTEND_CALLBACK                                0x10D0

struct tee_callback_param {
	uint32_t client_id;
	uint32_t context_id;
	uint32_t func_id;
	uint32_t cmd_id;
	uint32_t ret_size;
	uint8_t *in_buff;
	uint32_t in_size;
	uint8_t *out_buff;
	uint32_t out_size;
};

/* =========================== MUTEX ============================= */
#define TEE_EXTEND_MUTEX                                   0x10E0

struct tee_mutex_param {
	uint32_t lock;
};

/* =========================== SHM ============================= */
#define TEE_EXTEND_SHM_MMAP                                0x10F0
#define TEE_EXTEND_SHM_MUNMAP                              0x10F1

struct tee_shm_param {
	uint32_t pa;
	uint32_t va;
	uint32_t size;
};

/* ========================= NAGRA CERT ============================ */
#define TEE_EXTEND_NAGRA_CERT_LOCK                         0x1100
#define TEE_EXTEND_NAGRA_CERT_UNLOCK                       0x1101
#define TEE_EXTEND_NAGRA_CERT_RESET                        0x1102
#define TEE_EXTEND_NAGRA_CERT_EXCHANGE                     0x1103

struct tee_nagra_cert_lock_params {
	TEE_Nagra_Cert_Handle handle;
};

struct tee_nagra_cert_exchange_params {
	TEE_Nagra_Cert_Handle handle;
	size_t cmd_num;
	cert_command_t *commands;
	size_t *cmds_processed;
};

/* ========================= RNG APIs =========================== */
#define TEE_EXTEND_READ_RNG                                0x2000
struct tee_read_rng_param {
	uint8_t *buff;
	uint32_t size;
};

/* =========================== MAILBOX ============================ */
#define TEE_EXTEND_MAILBOX_SEND                            0x2010
#define TEE_EXTEND_MAILBOX_RECV                            0x2011

struct tee_mailbox_param {
	uint8_t *buff;
	uint32_t size;
};

/* ========================= STORAGE SYNC ========================== */
#define TEE_EXTEND_STORAGE_SYNC                            0x2020

/* ========================= CAS GENERIC =========================== */
#define TEE_EXTEND_GET_CAS_ID                              0x1110

struct tee_cas_id_params {
	cas_id_t type;
	uint8_t *id;
	uint32_t len;
};

#endif
