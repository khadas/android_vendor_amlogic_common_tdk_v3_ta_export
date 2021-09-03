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

#ifndef TEE_API_EXTENSIONS_H
#define TEE_API_EXTENSIONS_H

#include <types_ext.h>
#include <tee_api_types_extensions.h>
#include <utee_type_extensions.h>

/* ================================ EFUSE API ================================ */

/*
 * Desc: read efuse data, this function can only read TEE data in efuse user part
 *
 * Input:
 * offset: the offset of data to read, must aligned with 16
 * size: the size to read, must aligned with 16
 *
 * Output:
 * outbuf: output buffer for data
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Efuse_Read_Tee(uint8_t *outbuf, uint32_t offset, size_t size);

/*
 * Desc: read efuse data, this function can only read REE data in efuse user part
 *
 * Input:
 * offset: the offset of data to read, must aligned with 16
 * size: the size to read, must aligned with 16
 *
 * Output:
 * outbuf: output buffer for data
 *
 * Return: TEE_SUCCESS if suceess
 */
/* Please use new API TEE_Efuse_Read_User */
#define TEE_Efuse_Read_Ree TEE_Efuse_Read_User
TEE_Result TEE_Efuse_Read_User(uint8_t *outbuf, uint32_t offset, size_t size);

/*
 * Desc: read efuse data
 *
 * Input:
 * offset: the offset of data to read
 * size: the size to read
 *
 * Output:
 * outbuf: output buffer for data
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Efuse_Read(uint8_t *outbuf, uint32_t offset, size_t size);

/*
 * Desc: write one efuse block
 *
 * Input:
 * inbuf: the 16 byte data to write
 * block: the block index to write
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Efuse_Write_Block(uint8_t *inbuf, uint32_t block);

/* ================================ UNIFY API ================================ */
/*
 * Desc: Read unifykey by name
 *
 * Input:
 * name: the unifykey name
 * namelen: the unifykey name length
 * buflen: the buffer length
 *
 * Output:
 * buf: the output buffer
 * readlen: the read length
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Unify_Read(uint8_t *name, uint32_t namelen,
		uint8_t *buf, uint32_t buflen,
		uint32_t *readlen);

/* ================================ HDCP API ================================ */
#define TEE_HDCP_KEY_TYPE_TX14		0x1
#define TEE_HDCP_KEY_TYPE_TX22		0x2
#define TEE_HDCP_KEY_TYPE_RX14		0x3
#define TEE_HDCP_KEY_TYPE_RX22_FW_PRIVATE		0x6

#define TEE_HDCP_MODE_INVALID		0x0
#define TEE_HDCP_MODE_14		0x1
#define TEE_HDCP_MODE_22		0x2
#define TEE_HDCP_MODE_BUILDIN		0xFF
#define TEE_HDCP_AUTH_SUCCESS		0x1
#define TEE_HDCP_AUTH_FAILED		0x0

/*
 * Desc: get HDCP mode and authenticated status
 *
 * Output:
 * mode: current HDCP mode
 * auth: is HDCP authenticated
 *
 * Return: TEE_SUCCESS if suceess
 *
 * Note:
 *     mode = TEE_HDCP_MODE_14, auth = TEE_HDCP_AUTH_SUCCESS, HDCP 1.4 authenticated
 *     mode = TEE_HDCP_MODE_22, auth = TEE_HDCP_AUTH_SUCCESS, HDCP 2.2 authenticated
 *     mode = TEE_HDCP_MODE_BUILDIN, auth = TEE_HDCP_AUTH_SUCCESS, tv chips without hdmi tx
 *     mode = TEE_HDCP_MODE_INVALID, auth = TEE_HDCP_AUTH_FAILED, HDCP authentication failed
 */
TEE_Result TEE_HDCP_Get_State(uint32_t *mode, uint32_t *auth);

/*
 * Desc: load HDCP key to BL31 HDCP driver
 *
 * Input:
 * type: the key type to load
 * keybuf: HDCP key buffer
 * keylen: HDCP key buffer length
 *
 * Return: TEE_SUCCESS if suceess
 *
 * Note:
 *     type = TEE_HDCP_KEY_TYPE_TX14, load HDCP tx1.4 key
 *     type = TEE_HDCP_KEY_TYPE_TX22, load HDCP tx2.2 key
 *     type = TEE_HDCP_KEY_TYPE_RX14, load HDCP rx1.4 key
 *     type = TEE_HDCP_KEY_TYPE_RX22, load HDCP rx2.2 key
 */
TEE_Result TEE_HDCP_Load_Key(uint32_t type, uint8_t *keybuf, uint32_t keylen);

/*
 * Desc: set HDCP streaming ID
 *
 * Input:
 * type: the streaming ID
 *
 * Return: TEE_SUCCESS if suceess
 *
 * Note:
 *     type = 0x00, Type 0 Content Stream
 *     type = 0x01, Type 1 Content Stream
 *     type = 0x02~0xFF, Reserved for future use only
 */
TEE_Result TEE_HDCP_Set_StreamID(uint32_t type);

/*
 * Desc: get HDCP streaming ID
 *
 * Output:
 * type: the streaming ID
 *
 * Return: TEE_SUCCESS if suceess
 *
 */
TEE_Result TEE_HDCP_Get_StreamID(uint32_t *type);

/*
 * Desc: get HDMI plugin status
 *
 * Output:
 * state: the HDMI plugin status
 *
 * Return: TEE_SUCCESS if suceess
 *
 * Note:
 * state = 1 plugged in
 * state = 0 not plugged in
 */
TEE_Result TEE_HDMI_Get_State(uint32_t *state, uint32_t *reserved);

/* ================================ VIDEO FIRMWARE API ================================ */
/*
 * Desc: load video firmware to TEE memory
 *
 * Input:
 * firmware: the video firmware data
 * fw_size:  the video firmware data size
 * info: the array(struct tee_video_fw_info info[]) to describe the firmware data
 * info_size: the array size of info
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Video_Load_FW(uint8_t *firmware, uint32_t fw_size,
			uint8_t *info, uint32_t info_size);

/* ================================ TVP API ================================ */
/*
 * Desc: get vdec memory info
 *
 * Output:
 * info: the vdec info
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Vdec_Get_Info(tee_vdec_info_t *info);

/*
 * Desc: open a TVP channel
 *
 * Input:
 * cfg: the TVP channel config
 *
 * Return: TVP handle if suceess
 */
TEE_Tvp_Handle TEE_Tvp_Open_Channel(tvp_channel_cfg_t *cfg);

/*
 * Desc: close a TVP channel
 *
 * Input:
 * handle: the TVP handle
 *
 * Return: none
 */
void TEE_Tvp_Close_Channel(TEE_Tvp_Handle handle);

/*
 * Desc: bind TA's UUID to TVP channel
 *
 * Input:
 * handle: the TVP handle
 * uuid: the TA's UUID
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Tvp_Bind_Channel(TEE_Tvp_Handle handle, TEE_UUID *uuid);

/*
 * Desc: map vdec memory to TA's user space, no cached
 *
 * Input:
 * pa: the vdec memory physical address
 * size:  the vdec memory size
 *
 * Output:
 * va: the virtual address of vdec memory
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Vdec_Mmap(paddr_t pa, size_t size, vaddr_t *va);

/*
 * Desc: map vdec memory to TA's user space, cached
 *
 * Input:
 * pa: the vdec memory physical address
 * size:  the vdec memory size
 *
 * Output:
 * va: the virtual address of vdec memory
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Vdec_Mmap_Cached(paddr_t pa, size_t size, vaddr_t *va);

/*
 * Desc: unmap vdec memory from TA's user space
 *
 * Input:
 * pa: the vdec memory physical address
 * size:  the vdec memory size
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Vdec_Munmap(paddr_t pa, size_t size);

/*
 * Desc: get the video size
 *
 * Output:
 * width: the video width
 * height:  the video height
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Tvp_Get_Video_Size(uint32_t *width, uint32_t *height);

/*
 * Desc: get the display size
 *
 * Output:
 * width: the display width
 * height:  the display height
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Tvp_Get_Display_Size(uint32_t *width, uint32_t *height);

/*
 * Desc: set video layer
 *
 * Input:
 * video_layer: the video layer, 1 or 2
 * enable: 1 to enable video layer, 0 to disable video layer
 * flags: reserved
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Tvp_Set_Video_Layer(uint32_t video_layer, uint32_t enable, uint32_t flags);

/*
 * Desc: get video layer status
 *
 * Input:
 * video_layer: the video layer, 1 or 2
 *
 * Output:
 * enabled:  whether the video layer enabled
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Tvp_Get_Video_Layer(uint32_t video_layer, uint32_t *enabled);

/*
 * Desc: mute audio
 *
 * Input:
 * mute: 1 to mute, 0 to unmute
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Tvp_Set_Audio_Mute(uint32_t mute);

/*
 * Desc: get memory status by memory type
 *
 * Input:
 * type: memory type
 *
 * Output:
 * status: the memory status
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Tvp_Get_Status(uint32_t type, uint32_t *status);

/* ================================ KEYMASTER API ================================ */
/*
 * Desc: retrive boot parameters of keymaster which is stored in bl31 beforehand
 *
 * InOut:
 * boot_key_len: boot key size
 * boot_hash_len: boot key hash size
 *
 * Output:
 * locked: device locked state
 * boot_state: device boot state
 * boot_key: boot_key buffer
 * boot_hash: boot_key hash buffer
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Km_Get_Boot_Params(uint32_t *locked, uint32_t *boot_state,
		uint8_t *boot_key, uint32_t *boot_key_len,
		uint8_t *boot_hash, uint32_t *boot_hash_len);

/* ================================ DESCRAMBLER API =============================== */
/*
 * Desc: desc init
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Desc_Init(void);

/*
 * Desc: alloc desc channel
 *
 * Input:
 * desc_no: descrambler number
 *
 * Output:
 * fd: desc fd
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Desc_AllocChannel(int dsc_no, int *fd);

/*
 * Desc: free desc channel
 *
 * Input:
 * desc_no: descrambler number
 * fd: desc fd
 * algo: desc algo
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Desc_Set_Algo(int dsc_no, int fd, int algo);

/*
 * Desc: free desc channel
 *
 * Input:
 * desc_no: descrambler number
 * fd: desc fd
 * mode: desc mode
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Desc_Set_Mode(int dsc_no, int fd, int mode);

/*
 * Desc: free desc channel
 *
 * Input:
 * desc_no: descrambler number
 * fd: desc fd
 * pid: stream pid number need to desc
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Desc_Set_Pid(int dsc_no, int fd, int pid);

/*
 * Desc: free desc channel
 *
 * Input:
 * desc_no: descrambler number
 * fd: desc fd
 * parity: no use
 * key: key addr
 * key_type: 0 stands for odd, 1 even
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Desc_Set_Key(int dsc_no, int fd, int parity, uint8_t *key,
		uint32_t key_type);

/*
 * Desc: free desc channel
 *
 * Input:
 * module: desc number
 * output: dmx number to deliver the stream
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Desc_Set_Output(int module, int output);

/*
 * Desc: free desc channel
 *
 * Input:
 * desc_no: descrambler number
 * fd: desc fd
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Desc_FreeChannel(int dsc_no, int fd);

/*
 * Desc: free desc channel
 *
 * Input:
 * desc_no: descrambler number
 * all: channels need to reset
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Desc_Reset(int dsc_no, int all);

/*
 * Desc: desc exit
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Desc_Exit(void);

/*
 * Desc: Create a timer for TA
 *
 * Input:
 * cb: Timer callback after timeout
 * args: Arguments for callback
 * timeout: Timeout
 * flags: Flags
 *
 * Return NULL if any error, timer handle if success
 */
TEE_TimerHandle TEE_Timer_Create(tee_timer_cb_t cb, void *args,
		uint32_t timeout, uint32_t flags);

/*
 * Desc: Destroy a timer for TA
 *
 * Input:
 * handle: Timer handle
 *
 * Note: The timer must be destoryed before closing TA session,
 *       suggest that check and destory all TA timer
 *       in TA_CloseSessionEntryPoint()
 */
void TEE_Timer_Destroy(TEE_TimerHandle handle);

/* ================================ PROVISION API ================================ */
/*
 * Desc: cipher encrypt with kwrap
 *
 * Input:
 * iv: iv used to do encrypt
 * iv_len: iv size
 * src: source code need encrypt
 * src_len: source code size
 *
 * Output:
 * dst: encrypted code
 * dst_len: encrypted code size
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_CipherEncrypt_With_Kwrap(const uint8_t *iv, uint32_t iv_len,
		const uint8_t *src, uint32_t src_len, uint8_t *dst, uint32_t *dst_len);

/*
 * Desc: cipher decrypt with kwrap
 *
 * Input:
 * iv: iv used to do decrypt
 * iv_len: iv size
 * src: source code need decrypt
 * src_len: source code size
 *
 * Output:
 * dst: decrypted code
 * dst_len: decrypted code size
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_CipherDecrypt_With_Kwrap(const uint8_t *iv, uint32_t iv_len,
		const uint8_t *src, uint32_t src_len, uint8_t *dst, uint32_t *dst_len);

/*
 * Desc: AE decrypt with kwrap
 *
 * Input:
 * algorithm: TEE_ALG_AES_GCM
 * iv: iv used to do decrypt
 * iv_len: iv size
 * src: source code need decrypt
 * src_len: source code size
 * tag: tag to be compared
 * tag_len: tag size
 *
 * Output:
 * dst: decrypted code
 * dst_len: decrypted code size
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_AEDecrypt_With_Derived_Kwrap(uint32_t algorithm,
		uint8_t *iv, uint32_t ivlen,
		uint8_t *src, uint32_t srclen,
		uint8_t *dst, uint32_t len,
		uint8_t *tag, uint32_t taglen);

/*
 * Desc: cipher decrypt with ksecret
 *
 * Input:
 * iv: iv used to do decrypt
 * iv_len: iv size
 * src: source code need decrypt
 * src_len: source code size
 * tag: tag to be compared
 * tag_len: tag size
 *
 * Output:
 * dst: decrypted code
 * dst_len: decrypted code size
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_AEDecrypt_With_Derived_Ksecret(uint32_t algorithm,
		uint8_t *iv, uint32_t ivlen,
		uint8_t *src, uint32_t srclen,
		uint8_t *dst, uint32_t len,
		uint8_t *tag, uint32_t taglen);

/* ================================ KEYTABLE API ================================ */
/*
 * Desc: alloc key entry in key table
 *
 * Input:
 * flag: key table allocate flag
 *
 * Output:
 * handle: key table entry handle
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Keytable_Alloc(uint32_t flag, uint32_t *handle);

/*
 * Desc: configure the given key table
 *
 * Input:
 * handle: key table entry handle
 * cfg: key table configuration pointer
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Keytable_Config(uint32_t handle, tee_key_cfg_t *cfg);

/*
 * Desc: set key in key table
 *
 * Input:
 * handle: key table entry handle
 * key: key data
 * keylen: length of key
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Keytable_Set_Key(uint32_t handle, uint8_t *key, uint32_t keylen);

/*
 * Desc: free key entry in key table
 *
 * Input:
 * handle: key table entry handle
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Keytable_Free(uint32_t handle);

/*
 * Desc: cipher encrypt with key table
 *
 * Input:
 * algo: the algo
 * iv: iv used to do encrypt
 * iv_len: iv size
 * src: source code need encrypt
 * src_len: source code size
 * thread: crypto DMA thread, default with CRYPTO_DMA_THREAD_DEFAULT
 *
 * Output:
 * dst: encrypted code
 * dst_len: encrypted code size
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_CipherEncrypt_With_KT(uint32_t handle, uint32_t algo,
		const uint8_t *iv, uint32_t iv_len,
		const uint8_t *src, uint32_t src_len,
		uint8_t *dst, uint32_t *dst_len,
		uint32_t thread);

/*
 * Desc: cipher decrypt with key table
 *
 * Input:
 * algo: the algo
 * iv: iv used to do decrypt
 * iv_len: iv size
 * src: source code need decrypt
 * src_len: source code size
 * thread: crypto DMA thread, default with CRYPTO_DMA_THREAD_DEFAULT
 *
 * Output:
 * dst: decrypted code
 * dst_len: decrypted code size
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_CipherDecrypt_With_KT(uint32_t handle, uint32_t algo,
		const uint8_t *iv, uint32_t iv_len,
		const uint8_t *src, uint32_t src_len,
		uint8_t *dst, uint32_t *dst_len,
		uint32_t thread);

/*
 * Desc: cipher encrypt with key table extension
 *
 * Input:
 * algo: the algo
 * key_len: the length of key
 * iv: iv used to do encrypt
 * iv_len: iv size
 * src: source code need encrypt
 * src_len: source code size
 * thread: crypto DMA thread, default with CRYPTO_DMA_THREAD_DEFAULT
 * user_param: extra place holder for crypto engine that is not belong to standard
 * user_param_len: length of user param
 *
 * Output:
 * dst: encrypted code
 * dst_len: encrypted code size
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_CipherEncrypt_With_KT_EXT(
		uint32_t handle, uint32_t algo,
		uint32_t key_len,
		const uint8_t *iv, uint32_t iv_len,
		const uint8_t *src, uint32_t src_len,
		uint8_t *dst, uint32_t *dst_len,
		uint32_t thread,
		const uint8_t *user_param, uint32_t user_param_len);

/*
 * Desc: cipher decrypt with key table extension
 *
 * Input:
 * algo: the algo
 * key_len: the length of key
 * iv: iv used to do decrypt
 * iv_len: iv size
 * src: source code need decrypt
 * src_len: source code size
 * thread: crypto DMA thread, default with CRYPTO_DMA_THREAD_DEFAULT
 * user_param: extra place holder for crypto engine that is not belong to standard
 * user_param_len: length of user param
 *
 * Output:
 * dst: decrypted code
 * dst_len: decrypted code size
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_CipherDecrypt_With_KT_EXT(
		uint32_t handle, uint32_t algo,
		uint32_t key_len,
		const uint8_t *iv, uint32_t iv_len,
		const uint8_t *src, uint32_t src_len,
		uint8_t *dst, uint32_t *dst_len,
		uint32_t thread,
		const uint8_t *user_param, uint32_t user_param_len);

/*
* Desc: get key status in key table
*
* Input:
* handle: key table entry handle
* status: key status
*
* Return: TEE_SUCCESS if suceess
*/
TEE_Result TEE_Keytable_Get_Status(uint32_t handle, uint32_t *status);

/*
 * Desc: invalidate key entry in key table
 *
 * Input:
 * handle: key table entry handle
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Keytable_Invalidate(uint32_t handle);

/* ============================= KEYLADDER API ============================= */
/*
 * Desc: run key ladder and install key to key table entry
 *
 * Input:
 * p_conf: the key ladder configuration
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_KL_Run_V2(tee_kl_run_conf_t *p_conf);

/*
 * Desc: get key ladder challenge-response value
 *
 * Input:
 * p_conf: the key ladder CR configuration
 *
 * Output:
 * dnonce: the response dnonce value
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_KL_GetResponseToChallenge_V2(
		tee_kl_cr_conf_t *p_conf,
		uint8_t dnonce[16]);

/*
 * Desc: run nagra key ladder and install key to key table entry
 *
 * Input:
 * p_conf: the key ladder configuration
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_KL_Run_NV(tee_kl_run_conf_nv_t *p_conf);

/* ============================= NexGuard Watermark API ============================= */
/*
 * Desc: Provide the watermark HAL interface structure
 *
 * Return: A constant pointer to the NexGuard watermark HAL interface structure
 */
const INgwmHal* ngwmGetHalInterface(void);

/* ============================= Verimatrix Watermark API ============================= */
/*
 * Desc: Initialize verimatrix watermark
 *
 * Return: VM_HW_OK if suceess
 */
VM_HW_Err_t VM_HW_Init(void);

/*
 * Desc: Terminate Verimatrix watermark
 *
 * Return: VM_HW_OK if suceess
 */
VM_HW_Err_t VM_HW_Term(void);

/*
 * Desc: Open Verimatrix watermark session
 *
 * Input:
 * bServiceIdx: service index
 *
 * Return: VM_HW_OK if suceess
 */
VM_HW_Err_t VM_HW_OpenSession(uint8_t bServiceIdx);

/*
 * Desc: Close Verimatrix watermark session
 *
 * Input:
 * bServiceIdx: service index
 *
 * Return: VM_HW_OK if suceess
 */
VM_HW_Err_t VM_HW_CloseSession(uint8_t bServiceIdx);

/*
 * Desc: Set Verimatrix watermark parameters
 *
 * Input:
 * bServiceIdx: service index
 * hwParameters: parameters data
 *
 * Return: VM_HW_OK if suceess
 */
VM_HW_Err_t VM_HW_SetParameters_Rend(uint8_t bServiceIdx, vmx_hw_soc_rend_t* hwParameters);

/*
 * Desc: Set Verimatrix watermark last parameters
 *
 * Input:
 * bServiceIdx: service index
 * arg: parameters data
 * len: parameters data size
 *
 * Return: VM_HW_OK if suceess
 */
VM_HW_Err_t VM_HW_SetParameters_Last(uint8_t bServiceIdx, uint8_t *arg, unsigned int len);

/*
 * Desc: Set CWC
 *
 * Input:
 * bServiceIdx: service index
 * Kwmcwc: cwc
 * len: cwc size
 * klStage: keyladder stage
 *
 * Return: VM_HW_OK if suceess
 */
VM_HW_Err_t VM_HW_SetCWC(uint8_t bServiceIdx, uint8_t* Kwmcwc, size_t len, uint8_t klStage);

/* ============================== CALLBACK API ============================== */
/*
 * Desc: support RPC REE callback
 *
 * Input:
 * paramTypes: param types
 * params: input, output params
 *
 * Return: TEE_SUCCESS if success
 */
TEE_Result TEE_Callback(uint32_t paramTypes, TEE_Param params[TEE_NUM_PARAMS]);

/* ============================== MUTEX LOCK API ============================= */
/*
 * Desc: mutex lock
 *
 * Return: TEE_SUCCESS if success
 */
TEE_Result TEE_Mutex_Lock(void);

/*
 * Desc: mutex unlock
 *
 * Return: TEE_SUCCESS if success
 */
TEE_Result TEE_Mutex_Unlock(void);

/*
 * Desc: map the shm to TA permanently until TEE_Shm_Munmap is called
 *
 * Input:
 * va: the shm virtual address
 * size: the size of shm
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Shm_Mmap(uint32_t va, uint32_t size);

/*
 * Desc: ummap the shm
 *
 * Input:
 * va: the shm virtual address
 * size: the size of shm
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Shm_Munmap(uint32_t va, uint32_t size);

/*
 * Desc: get random number from HW RNG
 *
 * Input:
 * randomBuffer: buff for random number
 * randomBufferLen: buff length
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_ReadRngPool(void *randomBuffer, uint32_t randomBufferLen);

/*
 * Desc: TEE<->SECPU mailbox send
 *
 * Input:
 * inbuf: buff sent to mailbox
 * inlen: length of inbuf, must aligned with 4
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Mailbox_Send(uint8_t *inbuf, uint32_t inlen);

/*
 * Desc: TEE<->SECPU mailbox receive
 *
 * Input:
 * outbuf: buff receive from mailbox
 * outlen: length of outbuf
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Mailbox_Recv(uint8_t *outbuf, uint32_t *outlen);

/* ============================ STORAGE SYNC API =========================== */
/*
 * Desc: storage sync
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_SyncPersistentObject(void);

/*
 * Desc: CERT Lock
 *
 * Output:
 * handle: cert handle
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Nagra_Cert_Lock(TEE_Nagra_Cert_Handle *handle);

/*
 * Desc: CERT Unlock
 *
 * Output:
 * handle: cert handle
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Nagra_Cert_Unlock(TEE_Nagra_Cert_Handle handle);

/*
 * Desc: CERT Reset
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Nagra_Cert_Reset(void);

/*
 * Desc: CERT Unlock
 *
 * Input:
 * handle: CERT handle to process
 * cmd_num: command num to process
 * commands: data to process
 *
 * Output:
 * cmds_processed: processed command num
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Nagra_Cert_Exchange(TEE_Nagra_Cert_Handle handle, size_t cmd_num,
		cert_command_t *commands, size_t *cmds_processed);

/*
 * Desc: Read out ID for CAS or keys
 *
 * Input:
 * type: CAS or key type
 * id: buffer to hold id
 * len: length of id buffer
 *
 * Output:
 * id: id will hold the requested ID
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_Get_CAS_ID(uint32_t type, uint8_t *id, uint32_t len);

/*
 * Desc: Derive key by MKL which is setup with MSR/ETSI mode
 *
 * Input:
 * param: parameters for deriving key
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_MKL_MSR_Derive_Key(tee_mkl_msr_derive_key_param_t *param);

/*
 * Desc: Read data from NSK memory
 *
 * Input:
 * mem_type: memory area (nsk memory, secure top)
 * output: buff read from NSK memory
 * offset: Offset from the base of NSK memory
 * size: length of output, Number of bytes
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_NSK_Read8(nsk_mem_type_t mem_type, uint8_t *output, uint32_t offset, size_t size);

/*
 * Desc: Read data from NSK memory
 *
 * Input:
 * mem_type: memory area (nsk memory, secure top)
 * output: buff read from NSK memory
 * offset: Offset from the base of NSK memory
 * size: length of output, Number of 32-bit words
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_NSK_Read32(nsk_mem_type_t mem_type, uint32_t *output, uint32_t offset, size_t size);

/*
 * Desc: Write data to NSK memory
 *
 * Input:
 * mem_type: memory area (nsk memory, secure top)
 * input: buff to write to NSK memory
 * offset: Offset from the base of NSK memory
 * size: length of input, Number of bytes
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_NSK_Write8(nsk_mem_type_t mem_type, uint8_t *input, uint32_t offset, size_t size);

/*
 * Desc: Write data to NSK memory
 *
 * Input:
 * mem_type: memory area (nsk memory, secure top)
 * input: buff to write to NSK memory
 * offset: Offset from the base of NSK memory
 * size: length of input, Number of 32-bit words
 *
 * Return: TEE_SUCCESS if suceess
 */
TEE_Result TEE_NSK_Write32(nsk_mem_type_t mem_type, uint32_t *input, uint32_t offset, size_t size);

#endif
