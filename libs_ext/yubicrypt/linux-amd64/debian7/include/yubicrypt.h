/*
* Copyright (c) 2016 Yubico AB
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are
* met:
*
*   * Redistributions of source code must retain the above copyright
*     notice, this list of conditions and the following disclaimer.
*
*   * Redistributions in binary form must reproduce the above
*     copyright notice, this list of conditions and the following
*     disclaimer in the documentation and/or other materials provided
*     with the distribution.
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
*
*/

/**
 @mainpage

 @section Intro Introduction

 Libyubicrypt is a library for communication with a yubicrypt device.

 @section api API Reference

 yubicrypt.h
 All public functions and definitions

 */

/** @file yubicrypt.h
 *
 * Everything you need for yubicrypt.
 */

#ifndef YUBICRYPT_H
#define YUBICRYPT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/// Length of context array for authentication
#define YC_CONTEXT_LEN 16
/// Length of host challenge for authentication
#define YC_HOST_CHAL_LEN 8
/// Maximum length of message buffer
#define YC_MSG_BUF_SIZE 2048
/// Length of authentication keys
#define YC_KEY_LEN 16
/// Device vendor ID
#define YC_VID 0x1050
/// Device product ID
#define YC_PID 0x0030
/// Response flag for commands
#define YC_CMD_RESP_FLAG 0x80
/// Max items the device may hold
#define YC_MAX_ITEMS_COUNT                                                     \
  256 // TODO: should this really be defined in the API?
/// Max sessions the device may hold
#define YC_MAX_SESSIONS 16 // TODO: same here, really part of the API?
/// Default encryption key
#define YC_DEFAULT_ENC_KEY                                                     \
  "\x09\x0b\x47\xdb\xed\x59\x56\x54\x90\x1d\xee\x1c\xc6\x55\xe4\x20"
/// Default MAC key
#define YC_DEFAULT_MAC_KEY                                                     \
  "\x59\x2f\xd4\x83\xf7\x59\xe2\x99\x09\xa0\x4c\x45\x05\xd2\xce\x0a"
/// Default authentication key password
#define YC_DEFAULT_PASSWORD "password"
/// Salt to be used for PBKDF2 key derivation
#define YC_DEFAULT_SALT "Yubico"
/// Number of iterations for PBKDF2 key derivation
#define YC_DEFAULT_ITERS 10000
/// Length of capabilities array
#define YC_CAPABILITIES_LEN 8
/// Max log entries the device may hold
#define YC_MAX_LOG_ENTRIES 64 // TODO: really part of the API?
/// Length of object labels
#define YC_OBJ_LABEL_LEN 32

// Debug levels
/// No messages
#define YC_VERB_QUIET 0x00
/// Intermediate results
#define YC_VERB_INTERMEDIATE 0x01
/// Crypto results
#define YC_VERB_CRYPTO 0x02
/// Raw messages
#define YC_VERB_RAW 0x04
/// General info
#define YC_VERB_INFO 0x08
/// Error messages
#define YC_VERB_ERR 0x10
/// All previous options enabled
#define YC_VERB_ALL 0xff

#ifdef __cplusplus
extern "C" {
#endif

/// Reference to a connector
typedef struct yc_connector yc_connector;

/// Reference to a session
typedef struct yc_session yc_session;

/// Capabilitites representation
typedef struct {
  /// Capabilities is represented as an 8 byte uint8_t array
  uint8_t capabilities[YC_CAPABILITIES_LEN];
} yc_capabilities;

/**
 * Error codes.
 **/
typedef enum {
  /// Success
  YCR_SUCCESS = 0,
  /// Memory error
  YCR_MEMORY = -1,
  /// Init error
  YCR_INIT_ERROR = -2,
  /// Net error
  YCR_NET_ERROR = -3,
  /// Connector not found
  YCR_CONNECTOR_NOT_FOUND = -4,
  /// Invalid parameters
  YCR_INVALID_PARAMS = -5,
  /// Wrong length
  YCR_WRONG_LENGTH = -6,
  /// Buffer too small
  YCR_BUFFER_TOO_SMALL = -7,
  /// Cryptogram error
  YCR_CRYPTOGRAM_MISMATCH = -8,
  /// Authenticate session error
  YCR_AUTH_SESSION_ERROR = -9,
  /// MAC not matching
  YCR_MAC_MISMATCH = -10,
  /// Device success
  YCR_DEVICE_OK = -11,
  /// Invalid command
  YCR_DEVICE_INV_COMMAND = -12,
  /// Malformed command / invalid data
  YCR_DEVICE_INV_DATA = -13,
  /// Invalid session
  YCR_DEVICE_INV_SESSION = -14,
  /// Message encryption / verification failed
  YCR_DEVICE_AUTH_FAIL = -15,
  /// All sessions are allocated
  YCR_DEVICE_SESSIONS_FULL = -16,
  /// Session creation failed
  YCR_DEVICE_SESSION_FAILED = -17,
  /// Storage failure
  YCR_DEVICE_STORAGE_FAILED = -18,
  /// Wrong length
  YCR_DEVICE_WRONG_LENGTH = -19,
  /// Wrong permissions for operation
  YCR_DEVICE_INV_PERMISSION = -20,
  /// Log buffer is full and forced audit is set
  YCR_DEVICE_LOG_FULL = -21,
  /// Object not found
  YCR_DEVICE_OBJ_NOT_FOUND = -22,
  /// Id use is illegal
  YCR_DEVICE_ID_ILLEGAL = -23,
  /// OTP submitted is invalid
  YCR_DEVICE_INVALID_OTP = -24,
  /// Device is in demo mode and has to be power cycled
  YCR_DEVICE_DEMO_MODE = -25,
  /// The command execution has not terminated
  YCR_DEVICE_CMD_UNEXECUTED = -26,
  /// Unknown error
  YCR_GENERIC_ERROR = -26,
} yc_rc;

/// Macro to define command and response command
#define ADD_COMMAND(c, v) c = v, c##_R = v | YC_CMD_RESP_FLAG

/**
 * Command definitions
 */
typedef enum {
  /// Echo
  ADD_COMMAND(YCC_ECHO, 0x01),
  /// Create session
  ADD_COMMAND(YCC_CREATE_SES, 0x03),
  /// Authenticate session
  ADD_COMMAND(YCC_AUTH_SES, 0x04),
  /// Session message
  ADD_COMMAND(YCC_SES_MSG, 0x05),
  /// Get device info
  ADD_COMMAND(YCC_GET_DEVICE_INFO, 0x06),
  /// BSL
  ADD_COMMAND(YCC_BSL, 0x07),
  /// Reset
  ADD_COMMAND(YCC_RESET, 0x08),
  /// Close session
  ADD_COMMAND(YCC_CLOSE_SES, 0x40),
  /// Storage statistics
  ADD_COMMAND(YCC_STATS, 0x041),
  /// Put opaque
  ADD_COMMAND(YCC_PUT_OPAQUE, 0x42),
  /// Get opaque
  ADD_COMMAND(YCC_GET_OPAQUE, 0x43),
  /// Put authentication key
  ADD_COMMAND(YCC_PUT_AUTHKEY, 0x44),
  /// Put asymmetric key
  ADD_COMMAND(YCC_PUT_ASYMMETRIC_KEY, 0x45),
  /// Generate asymmetric key
  ADD_COMMAND(YCC_GEN_ASYMMETRIC_KEY, 0x46),
  /// Sign data with PKCS1
  ADD_COMMAND(YCC_SIGN_DATA_PKCS1, 0x47),
  /// List objects
  ADD_COMMAND(YCC_LIST, 0x48),
  /// Decrypt data with PKCS1
  ADD_COMMAND(YCC_DECRYPT_PKCS1, 0x49),
  /// Export an object wrapped
  ADD_COMMAND(YCC_EXPORT_WRAPPED, 0x4a),
  /// Import a wrapped object
  ADD_COMMAND(YCC_IMPORT_WRAPPED, 0x4b),
  /// Put wrap key
  ADD_COMMAND(YCC_PUT_WRAP_KEY, 0x4c),
  /// Get audit logs
  ADD_COMMAND(YCC_GET_LOGS, 0x4d),
  /// Get object information
  ADD_COMMAND(YCC_GET_OBJECT_INFO, 0x4e),
  /// Put a global option
  ADD_COMMAND(YCC_PUT_OPTION, 0x4f),
  /// Get a global option
  ADD_COMMAND(YCC_GET_OPTION, 0x50),
  /// Get pseudo random data
  ADD_COMMAND(YCC_GET_PSEUDO_RANDOM, 0x51),
  /// Put HMAC key
  ADD_COMMAND(YCC_PUT_HMAC_KEY, 0x52),
  /// HMAC data
  ADD_COMMAND(YCC_HMAC_DATA, 0x53),
  /// Get a public key
  ADD_COMMAND(YCC_GET_PUBKEY, 0x54),
  /// Sign data with PSS
  ADD_COMMAND(YCC_SIGN_DATA_PSS, 0x55),
  /// Sign data with ECDSA
  ADD_COMMAND(YCC_SIGN_DATA_ECDSA, 0x56),
  /// Perform a ECDH exchange
  ADD_COMMAND(YCC_DECRYPT_ECDH, 0x57),
  /// Delete an object
  ADD_COMMAND(YCC_DELETE_OBJECT, 0x58),
  /// Decrypt data with OAEP
  ADD_COMMAND(YCC_DECRYPT_OAEP, 0x59),
  /// Generate HMAC key
  ADD_COMMAND(YCC_GENERATE_HMAC_KEY, 0x5a),
  /// Generate wrap key
  ADD_COMMAND(YCC_GENERATE_WRAP_KEY, 0x5b),
  /// Verify HMAC data
  ADD_COMMAND(YCC_VERIFY_HMAC, 0x5c),
  /// SSH Certify
  ADD_COMMAND(YCC_SSH_CERTIFY, 0x5d),
  /// Put template
  ADD_COMMAND(YCC_PUT_TEMPLATE, 0x5e),
  /// Get template
  ADD_COMMAND(YCC_GET_TEMPLATE, 0x5f),
  /// Decrypt OTP
  ADD_COMMAND(YCC_OTP_DECRYPT, 0x60),
  /// Create OTP AEAD
  ADD_COMMAND(YCC_OTP_AEAD_CREATE, 0x61),
  /// Create OTP AEAD from random
  ADD_COMMAND(YCC_OTP_AEAD_RANDOM, 0x62),
  /// Rewrap OTP AEAD
  ADD_COMMAND(YCC_OTP_AEAD_REWRAP, 0x63),
  /// Attest an asymmetric key
  ADD_COMMAND(YCC_ATTEST_ASYMMETRIC, 0x64),
  /// Put OTP AEAD key
  ADD_COMMAND(YCC_PUT_OTP_AEAD_KEY, 0x65),
  /// Generate OTP AEAD key
  ADD_COMMAND(YCC_GENERATE_OTP_AEAD_KEY, 0x66),
  /// Set log index
  ADD_COMMAND(YCC_SET_LOG_INDEX, 0x67),
  /// Wrap data
  ADD_COMMAND(YCC_WRAP_DATA, 0x68),
  /// Unwrap data
  ADD_COMMAND(YCC_UNWRAP_DATA, 0x69),
  /// Error
  YCC_ERROR = 0x7f,
} yc_cmd;

#undef ADD_COMMAND

/**
 * Object types
 */
typedef enum {
  /// Opaque object
  YC_OPAQUE = 0x01,
  /// Authentication key
  YC_AUTHKEY = 0x02,
  /// Asymmetric key
  YC_ASYMMETRIC = 0x03,
  /// Wrap key
  YC_WRAPKEY = 0x04,
  /// HMAC key
  YC_HMACKEY = 0x05,
  /// Template
  YC_TEMPLATE = 0x06,
  /// OTP AEAD key
  YC_OTP_AEAD_KEY = 0x07,
  /// Public key (virtual..)
  YC_PUBLIC = 0x83,
} yc_object_type;

/// Max number of algorithms defined here
#define YC_MAX_ALGORITHM_COUNT 40
/**
 * Algorithms
 */
typedef enum {
  YC_ALGO_RSA_PKCS1_SHA1 = 1,
  YC_ALGO_RSA_PKCS1_SHA256 = 2,
  YC_ALGO_RSA_PKCS1_SHA384 = 3,
  YC_ALGO_RSA_PKCS1_SHA512 = 4,
  YC_ALGO_RSA_PSS_SHA1 = 5,
  YC_ALGO_RSA_PSS_SHA256 = 6,
  YC_ALGO_RSA_PSS_SHA384 = 7,
  YC_ALGO_RSA_PSS_SHA512 = 8,
  YC_ALGO_RSA_2048 = 9,
  YC_ALGO_RSA_3072 = 10,
  YC_ALGO_RSA_4096 = 11,
  YC_ALGO_EC_P256 = 12,
  YC_ALGO_EC_P384 = 13,
  YC_ALGO_EC_P521 = 14,
  YC_ALGO_EC_K256 = 15,
  YC_ALGO_EC_BP256 = 16,
  YC_ALGO_EC_BP384 = 17,
  YC_ALGO_EC_BP512 = 18,
  YC_ALGO_HMAC_SHA1 = 19,
  YC_ALGO_HMAC_SHA256 = 20,
  YC_ALGO_HMAC_SHA384 = 21,
  YC_ALGO_HMAC_SHA512 = 22,
  YC_ALGO_EC_ECDSA = 23,
  YC_ALGO_EC_ECDH = 24,
  YC_ALGO_RSA_OAEP_SHA1 = 25,
  YC_ALGO_RSA_OAEP_SHA256 = 26,
  YC_ALGO_RSA_OAEP_SHA384 = 27,
  YC_ALGO_RSA_OAEP_SHA512 = 28,
  YC_ALGO_AES_CCM_WRAP = 29,
  YC_ALGO_OPAQUE_DATA = 30,
  YC_ALGO_OPAQUE_X509_CERT = 31,
  YC_ALGO_MGF1_SHA1 = 32,
  YC_ALGO_MGF1_SHA256 = 33,
  YC_ALGO_MGF1_SHA384 = 34,
  YC_ALGO_MGF1_SHA512 = 35,
  YC_ALGO_TEMPL_SSH = 36,
  YC_ALGO_YUBICO_OTP_AES128 = 37,
  YC_ALGO_SCP03_AUTH = 38,
  YC_ALGO_YUBICO_OTP_AES192 = 39,
  YC_ALGO_YUBICO_OTP_AES256 = 40,
} yc_algorithm;

/**
 * Global options
 */
typedef enum {
  /// Forced audit mode
  YC_OPTION_FORCE_AUDIT = 1,
  /// Audit logging enabled
  YC_OPTION_AUDIT_ENABLED = 2,
} yc_option;

/// Size that the log digest is truncated to
#define YC_LOG_DIGEST_SIZE 16
#pragma pack(push, 1)
/**
 * Logging struct as returned by device
 */
typedef struct {
  /// Monotonically increasing index
  uint16_t number;
  /// What command was executed @see yc_cmd
  uint8_t command;
  /// Length of in-data
  uint16_t length;
  /// ID of authentication key used
  uint16_t session_key;
  /// ID of first object used
  uint16_t target_key;
  /// ID of second object used
  uint16_t second_key;
  /// Command result @see yc_cmd
  uint8_t result;
  /// Systick at time of execution
  uint32_t systick;
  /// Truncated sha256 digest of this last digest + this entry
  uint8_t digest[YC_LOG_DIGEST_SIZE];
} yc_log_entry;

/**
 * Object descriptor
 */
typedef struct {
  /// Object capabilities @see yc_capabilities
  yc_capabilities capabilities;
  /// Object ID
  uint16_t id;
  /// Object length
  uint16_t len;
  /// Object domains
  uint16_t domains;
  /// Object type
  yc_object_type type;
  /// Object algorithm
  yc_algorithm algorithm;
  /// Object sequence
  uint8_t sequence;
  /// Object origin
  uint8_t origin;
  /// Object label
  uint8_t label[YC_OBJ_LABEL_LEN];
} yc_object_descriptor;
#pragma pack(pop)

static const struct {
  const char *name;
  int bit;
} yc_capability[] = {
  {"data_read", 0x00},
  {"data_write", 0x01},
  {"authkey_write", 0x02},
  {"asymmetric_write", 0x03},
  {"asymmetric_gen", 0x04},
  {"asymmetric_sign_pkcs", 0x05},
  {"asymmetric_sign_pss", 0x06},
  {"asymmetric_sign_ecdsa", 0x07},
  {"asymmetric_sign_decdsa", 0x08},
  {"asymmetric_decrypt_pkcs", 0x09},
  {"asymmetric_decrypt_oaep", 0x0a},
  {"asymmetric_decrypt_ecdh", 0x0b},
  {"export_wrapped", 0x0c},
  {"import_wrapped", 0x0d},
  {"put_wrapkey", 0x0e},
  {"generate_wrapkey", 0x0f},
  {"export_under_wrap", 0x10},
  {"option_write", 0x11},
  {"option_read", 0x12},
  {"get_randomness", 0x13},
  {"hmackey_write", 0x14},
  {"hmackey_generate", 0x15},
  {"hmac_data", 0x16},
  {"hmac_verify", 0x17},
  {"audit", 0x18},
  {"ssh_certify", 0x19},
  {"template_read", 0x1a},
  {"template_write", 0x1b},
  {"reset", 0x1c},
  {"otp_decrypt", 0x1d},
  {"otp_aead_create", 0x1e},
  {"otp_aead_random", 0x1f},
  {"otp_aead_rewrap_from", 0x20},
  {"otp_aead_rewrap_to", 0x21},
  {"attest", 0x22},
  {"put_otp_aead_key", 0x23},
  {"generate_otp_aead_key", 0x24},
  {"wrap_data", 0x25},
  {"unwrap_data", 0x26},
};

static const struct {
  const char *name;
  yc_algorithm algorithm;
} yc_algorithms[] = {
  {"rsa-pkcs1-sha1", YC_ALGO_RSA_PKCS1_SHA1},
  {"rsa-pkcs1-sha256", YC_ALGO_RSA_PKCS1_SHA256},
  {"rsa-pkcs1-sha384", YC_ALGO_RSA_PKCS1_SHA384},
  {"rsa-pkcs1-sha512", YC_ALGO_RSA_PKCS1_SHA512},
  {"rsa-pss-sha1", YC_ALGO_RSA_PSS_SHA1},
  {"rsa-pss-sha256", YC_ALGO_RSA_PSS_SHA256},
  {"rsa-pss-sha384", YC_ALGO_RSA_PSS_SHA384},
  {"rsa-pss-sha512", YC_ALGO_RSA_PSS_SHA512},
  {"rsa2048", YC_ALGO_RSA_2048},
  {"rsa3072", YC_ALGO_RSA_3072},
  {"rsa4096", YC_ALGO_RSA_4096},
  {"ecp256", YC_ALGO_EC_P256},
  {"ecp384", YC_ALGO_EC_P384},
  {"ecp521", YC_ALGO_EC_P521},
  {"eck256", YC_ALGO_EC_K256},
  {"ecbp256", YC_ALGO_EC_BP256},
  {"ecbp384", YC_ALGO_EC_BP384},
  {"ecbp512", YC_ALGO_EC_BP512},
  {"hmac-sha1", YC_ALGO_HMAC_SHA1},
  {"hmac-sha256", YC_ALGO_HMAC_SHA256},
  {"hmac-sha384", YC_ALGO_HMAC_SHA384},
  {"hmac-sha512", YC_ALGO_HMAC_SHA512},
  {"ecdsa", YC_ALGO_EC_ECDSA},
  {"ecdh", YC_ALGO_EC_ECDH},
  {"rsa-oaep-sha1", YC_ALGO_RSA_OAEP_SHA1},
  {"rsa-oaep-sha256", YC_ALGO_RSA_OAEP_SHA256},
  {"rsa-oaep-sha384", YC_ALGO_RSA_OAEP_SHA384},
  {"rsa-oaep-sha512", YC_ALGO_RSA_OAEP_SHA512},
  {"aes-ccm-wrap", YC_ALGO_AES_CCM_WRAP},
  {"opaque", YC_ALGO_OPAQUE_DATA},
  {"x509-cert", YC_ALGO_OPAQUE_X509_CERT},
  {"mgf1-sha1", YC_ALGO_MGF1_SHA1},
  {"mgf1-sha256", YC_ALGO_MGF1_SHA256},
  {"mgf1-sha384", YC_ALGO_MGF1_SHA384},
  {"mgf1-sha512", YC_ALGO_MGF1_SHA512},
  {"template-ssh", YC_ALGO_TEMPL_SSH},
  {"yubico-otp-aes128", YC_ALGO_YUBICO_OTP_AES128},
  {"scp03-auth", YC_ALGO_SCP03_AUTH},
  {"yubico-otp-aes192", YC_ALGO_YUBICO_OTP_AES192},
  {"yubico-otp-aes256", YC_ALGO_YUBICO_OTP_AES256},
};

static const struct {
  const char *name;
  yc_object_type type;
} yc_types[] = {
  {"opaque", YC_OPAQUE},           {"authkey", YC_AUTHKEY},
  {"asymmetric", YC_ASYMMETRIC},   {"wrapkey", YC_WRAPKEY},
  {"hmackey", YC_HMACKEY},         {"template", YC_TEMPLATE},
  {"otpaeadkey", YC_OTP_AEAD_KEY},
};

/// Origin is generated
#define YC_ORIGIN_GENERATED 0x01
/// Origin is imported
#define YC_ORIGIN_IMPORTED 0x02
/// Origin is wrapped (note: this is used in combination with objects original
/// origin)
#define YC_ORIGIN_IMPORTED_WRAPPED 0x10

/**
 * Return a string describing an error condition
 *
 * @param err yc_rc error code
 *
 * @return String with descriptive error
 **/
const char *yc_strerror(yc_rc err);

/**
 * Set verbosity
 *
 * @param verbosity
 *
 * @return yc_rc error code
 **/
yc_rc yc_set_verbosity(uint8_t verbosity);

/**
 * Get verbosity
 *
 * @param verbosity
 *
 * @return yc_rc error code
 **/
yc_rc yc_get_verbosity(uint8_t *verbosity);

/**
 * Global library initialization
 *
 * @return yc_rc error code
 **/
yc_rc yc_init(void);

/**
 * Global library cleanup
 *
 * @return yc_rc error code
 **/
yc_rc yc_exit(void);

/**
 * Connect to all specified connectors
 *
 * @param url array of URLs specifying connectors
 * @param n_url number of elements in url array
 * @param connector reference to pointer of connector array
 * @param n_connectors max number of connectors in array (will be set to
 *succesful connectors on return)
 * @param timeout timeout in seconds
 *
 * @return yc_rc error code
 **/
yc_rc yc_connect_all(char *url[], uint16_t n_url, yc_connector ***connector,
                     uint16_t *n_connectors, int timeout);

/**
 * Connect to one connector in array
 *
 * @param url array of URLs specifying connectors
 * @param n_url number of elements in connector array
 * @param connector reference to connector
 *
 * @return yc_rc error code
 **/
yc_rc yc_connect_best(char *url[], uint16_t n_url, yc_connector **connector);

/**
 * Disconnect from connector
 *
 * @param connector connector to disconnect from
 *
 * @return yc_rc error code
 **/
yc_rc yc_disconnect(yc_connector *connector);

/**
 * Send a plain message to a connector
 *
 * @param connector connector to send to
 * @param cmd command to send
 * @param data data to send
 * @param data_len data length
 * @param response_cmd response command
 * @param response response data
 * @param response_len response length
 *
 * @return yc_rc error code
 **/
yc_rc yc_send_plain_msg(yc_connector *connector, yc_cmd cmd,
                        const uint8_t *data, uint16_t data_len,
                        yc_cmd *response_cmd, uint8_t *response,
                        uint16_t *response_len);

/**
 * Send an encrypted message over a session
 *
 * @param session session to send over
 * @param cmd command to send
 * @param data data to send
 * @param data_len data length
 * @param response_cmd response command
 * @param response response data
 * @param response_len response length
 *
 * @return yc_rc error code
 **/
yc_rc yc_send_secure_msg(yc_session *session, yc_cmd cmd, const uint8_t *data,
                         uint16_t data_len, yc_cmd *response_cmd,
                         uint8_t *response, uint16_t *response_len);

/**
 * Create a session with keys derived frm password
 *
 * @param connector connector to create the session with
 * @param auth_keyset_id ID of the authentication key to be used
 * @param password password to derive keys from
 * @param context context data for the authentication
 * @param session created session
 *
 * @return yc_rc error code
 **/
yc_rc yc_create_session_derived(yc_connector *connector,
                                uint16_t auth_keyset_id, const char *password,
                                uint8_t context[YC_CONTEXT_LEN],
                                yc_session **session);

/**
 * Create a session
 *
 * @param connector connector to create the session with
 * @param auth_keyset_id ID of the authentication key
 * @param key_enc encryption key
 * @param key_enc_len length of encryption key
 * @param key_mac MAC key
 * @param key_mac_len length of MAC key
 * @param context context data for the authentication
 * @param session created session
 *
 * @return yc_rc error code
 **/
yc_rc yc_create_session(yc_connector *connector, uint16_t auth_keyset_id,
                        const uint8_t *key_enc, uint16_t key_enc_len,
                        const uint8_t *key_mac, uint16_t key_mac_len,
                        uint8_t context[YC_CONTEXT_LEN], yc_session **session);

/**
 * Begin create extenal session
 *
 * @param connector connector to create the session with
 * @param auth_keyset_id ID of the authentication key
 * @param context context data for the authentication
 * @param context_len length of context data
 * @param card_cryptogram card cryptogram
 * @param card_cryptogram_len catd cryptogram length
 * @param session created session
 *
 * @return yc_rc error code
 **/
yc_rc yc_begin_create_session_ext(yc_connector *connector,
                                  uint16_t auth_keyset_id, uint8_t *context,
                                  size_t context_len, uint8_t *card_cryptogram,
                                  size_t card_cryptogram_len,
                                  yc_session **session);

/**
 * Finish creating external session
 *
 * @param connector connector to create the session with
 * @param session session
 * @param key_senc session encryption key
 * @param key_senc_len session encrypt key length
 * @param key_smac session MAC key
 * @param key_smac_len session MAC key length
 * @param key_srmac session return MAC key
 * @param key_srmac_len session return MAC key length
 * @param context context data
 * @param card_cryptogram card cryptogram
 * @param card_cryptogram_len card cryptogram length
 *
 * @return yc_rc error code
 **/
yc_rc yc_finish_create_session_ext(
  yc_connector *connector, yc_session *session, const uint8_t *key_senc,
  uint16_t key_senc_len, const uint8_t *key_smac, uint16_t key_smac_len,
  const uint8_t *key_srmac, uint16_t key_srmac_len,
  uint8_t context[YC_CONTEXT_LEN], uint8_t *card_cryptogram,
  size_t card_cryptogram_len);

/**
 * Free data associated with session
 *
 * @param session session to destroy
 *
 * @return yc_rc error code
 **/
yc_rc yc_destroy_session(yc_session *session);

/**
 * Authenticate session
 *
 * @param session session to authenticate
 * @param context context data
 *
 * @return yc_rc error code
 **/
yc_rc yc_authenticate_session(yc_session *session,
                              uint8_t context[YC_CONTEXT_LEN]);

// Utility and convenience functions below

/**
 * Get device info
 *
 * @param connector connector to send over
 * @param major version major
 * @param minor version minor
 * @param patch version path
 * @param serial serial number
 * @param log_total total number of log entries
 * @param log_used log entries used
 * @param algorithms algorithms array
 * @param n_algorithms number of algorithms
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_get_device_info(yc_connector *connector, uint8_t *major,
                              uint8_t *minor, uint8_t *patch, uint32_t *serial,
                              uint8_t *log_total, uint8_t *log_used,
                              yc_algorithm *algorithms, size_t *n_algorithms);

/**
 * List objects
 *
 * @param session session to use
 * @param id ID to filter by (0 to not filter by ID)
 * @param type Type to filter by (0 to not filter by type) @see yc_object_type
 * @param domains Domains to filter by (0 to not filter by domain)
 * @param capabilities Capabilities to filter by (0 to not filter by
 *capabilities) @see yc_capabilities
 * @param algorithm Algorithm to filter by (0 to not filter by algorithm)
 * @param label Label to filter by
 * @param label_len Length of label
 * @param objects Array of objects returned
 * @param n_objects Max length of objects (will be set to number found on
 *return)
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_list_objects(yc_session *session, uint16_t id,
                           yc_object_type type, uint16_t domains,
                           const yc_capabilities *capabilities,
                           yc_algorithm algorithm, const uint8_t *label,
                           size_t label_len, yc_object_descriptor *objects,
                           uint16_t *n_objects);

/**
 * Get object info
 *
 * @param session session to use
 * @param id Object ID
 * @param type Object type
 * @param found if object was found
 * @param object object information
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_get_object_info(yc_session *session, uint16_t id,
                              yc_object_type type, bool *found,
                              yc_object_descriptor *object);

/**
 * Get Public key
 *
 * @param session session to use
 * @param id Object ID
 * @param data Data out
 * @param datalen Data length
 * @param algorithm Algorithm of object
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_get_pubkey(yc_session *session, uint16_t id, uint8_t *data,
                         uint16_t *datalen, yc_algorithm *algorithm);

/**
 * Close session
 *
 * @param session session to close
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_close_session(yc_session *session);

/**
 * Sign data using PKCS1 v1.5
 *
 * @param session session to use
 * @param key_id Object ID
 * @param hashed if data is already hashed
 * @param in in data to sign
 * @param in_len length of in
 * @param out signed data
 * @param out_len length of signed data
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_sign_pkcs1v1_5(yc_session *session, uint16_t key_id, bool hashed,
                             const uint8_t *in, uint16_t in_len, uint8_t *out,
                             uint16_t *out_len);

/**
 * Sign data using RSS
 *
 * @param session session to use
 * @param key_id Object ID
 * @param in data to sign
 * @param in_len length of in
 * @param out signed data
 * @param out_len length of signed data
 * @param salt_len length of salt
 * @param mgf1Algo algorithm for mgf1
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_sign_pss(yc_session *session, uint16_t key_id, const uint8_t *in,
                       uint16_t in_len, uint8_t *out, uint16_t *out_len,
                       uint16_t salt_len, yc_algorithm mgf1Algo);

/**
 * SIgn data using ECDSA
 *
 * @param session session to use
 * @param key_id Object ID
 * @param in data to sign
 * @param in_len length of in
 * @param out signed data
 * @param out_len length of signed data
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_sign_ecdsa(yc_session *session, uint16_t key_id,
                         const uint8_t *in, uint16_t in_len, uint8_t *out,
                         uint16_t *out_len);

/**
 * HMAC data
 *
 * @param session session to use
 * @param key_id Object ID
 * @param in data to hmac
 * @param in_len length of in
 * @param out HMAC
 * @param out_len length of HMAC
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_hmac(yc_session *session, uint16_t key_id, const uint8_t *in,
                   uint16_t in_len, uint8_t *out, uint16_t *out_len);

/**
 * Get pseudo random data
 *
 * @param session session to use
 * @param len length of data to get
 * @param out random data out
 * @param out_len length of random data
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_get_random(yc_session *session, uint16_t len, uint8_t *out,
                         uint16_t *out_len);

/**
 * Import RSA key
 *
 * @param session session to use
 * @param key_id Object ID
 * @param label Label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities capabilities
 * @param algorithm algorithm
 * @param p P
 * @param q Q
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_import_key_rsa(yc_session *session, uint16_t *key_id,
                             const uint8_t *label, size_t label_len,
                             uint16_t domains,
                             const yc_capabilities *capabilities,
                             yc_algorithm algorithm, const uint8_t *p,
                             const uint8_t *q);

/**
 * Import EC key
 *
 * @param session session to use
 * @param key_id Object ID
 * @param label Label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities capabilities
 * @param algorithm algorithm
 * @param s S
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_import_key_ec(yc_session *session, uint16_t *key_id,
                            const uint8_t *label, size_t label_len,
                            uint16_t domains,
                            const yc_capabilities *capabilities,
                            yc_algorithm algorithm, const uint8_t *s);

/**
 * Import HMAC key
 *
 * @param session session to use
 * @param key_id Object ID
 * @param label Label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities capabilities
 * @param algorithm algorithm
 * @param key key data
 * @param keylen length of key
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_import_key_hmac(yc_session *session, uint16_t *key_id,
                              const uint8_t *label, size_t label_len,
                              uint16_t domains,
                              const yc_capabilities *capabilities,
                              yc_algorithm algorithm, const uint8_t *key,
                              uint16_t keylen);

/**
 * Generate RSA key
 *
 * @param session session to use
 * @param key_id Object ID
 * @param label Label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities capabilities
 * @param algorithm algorithm
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_generate_key_rsa(yc_session *session, uint16_t *key_id,
                               const uint8_t *label, size_t label_len,
                               uint16_t domains,
                               const yc_capabilities *capabilities,
                               yc_algorithm algorithm);

/**
 * Generate EC key
 *
 * @param session session to use
 * @param key_id Object ID
 * @param label Label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities capabilities
 * @param algorithm algorithm
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_generate_key_ec(yc_session *session, uint16_t *key_id,
                              const uint8_t *label, size_t label_len,
                              uint16_t domains,
                              const yc_capabilities *capabilities,
                              yc_algorithm algorithm);

/**
 * Verify HMAC data
 *
 * @param session session to use
 * @param key_id Object ID
 * @param signature HMAC
 * @param signature_len HMAC length
 * @param data data to verify
 * @param data_len data length
 * @param verified if verification succeeded
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_hmac_verify(yc_session *session, uint16_t key_id,
                          const uint8_t *signature, uint16_t signature_len,
                          const uint8_t *data, uint16_t data_len,
                          bool *verified);

/**
 * Generate HMAC key
 *
 * @param session session to use
 * @param key_id Object ID
 * @param label Label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities capabilities
 * @param algorithm algorithm
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_generate_key_hmac(yc_session *session, uint16_t *key_id,
                                const uint8_t *label, size_t label_len,
                                uint16_t domains,
                                const yc_capabilities *capabilities,
                                yc_algorithm algorithm);

/**
 * Decrypt PKCS1 v1.5 data
 *
 * @param session session to use
 * @param key_id Object ID
 * @param in Encrypted data
 * @param in_len length of encrypted data
 * @param out Decrypted data
 * @param out_len length of decrypted data
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_decrypt_pkcs1v1_5(yc_session *session, uint16_t key_id,
                                const uint8_t *in, uint16_t in_len,
                                uint8_t *out, uint16_t *out_len);

/**
 * Decrypt OAEP data
 *
 * @param session session to use
 * @param key_id Object ID
 * @param in Encrypted data
 * @param in_len length of encrypted data
 * @param out Decrypted data
 * @param out_len length of decrypted data
 * @param label OAEP label
 * @param label_len label length
 * @param mgf1Algo MGF1 algorithm
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_decrypt_oaep(yc_session *session, uint16_t key_id,
                           const uint8_t *in, uint16_t in_len, uint8_t *out,
                           uint16_t *out_len, const uint8_t *label,
                           uint16_t label_len, yc_algorithm mgf1Algo);

/**
 * Perform ECDH key exchange
 *
 * @param session session to use
 * @param key_id Object ID
 * @param in public key
 * @param in_len length of public key
 * @param out Agreed key
 * @param out_len length of agreed key
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_decrypt_ecdh(yc_session *session, uint16_t key_id,
                           const uint8_t *in, uint16_t in_len, uint8_t *out,
                           uint16_t *out_len);

/**
 * Delete an object
 *
 * @param session session to use
 * @param type Object type
 * @param id Object ID
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_delete_object(yc_session *session, yc_object_type type,
                            uint16_t id);

/**
 * Export an object under wrap
 *
 * @param session session to use
 * @param wrapping_key_id ID of wrapping key
 * @param target_type Type of object
 * @param target_id ID of object
 * @param out wrapped data
 * @param out_len length of wrapped data
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_export_wrapped(yc_session *session, uint16_t wrapping_key_id,
                             yc_object_type target_type, uint16_t target_id,
                             uint8_t *out, uint16_t *out_len);

/**
 * Import a wrapped object
 *
 * @param session session to use
 * @param wrapping_key_id ID of wrapping key
 * @param in wrapped data
 * @param in_len length of wrapped data
 * @param target_type what type the imported object has
 * @param target_id ID of imported object
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_import_wrapped(yc_session *session, uint16_t wrapping_key_id,
                             const uint8_t *in, uint16_t in_len,
                             yc_object_type *target_type, uint16_t *target_id);

/**
 * Import a wrap key
 *
 * @param session session to use
 * @param key_id Object ID
 * @param label label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities capabilities
 * @param in key
 * @param in_len key length
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_import_key_wrap(yc_session *session, uint16_t *key_id,
                              const uint8_t *label, size_t label_len,
                              uint16_t domains,
                              const yc_capabilities *capabilities,
                              const uint8_t *in, uint16_t in_len);

/**
 * Generate a wrap key
 *
 * @param session session to use
 * @param key_id Object ID
 * @param label label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities capabilities
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_generate_key_wrap(yc_session *session, uint16_t *key_id,
                                const uint8_t *label, size_t label_len,
                                uint16_t domains,
                                const yc_capabilities *capabilities);

/**
 * Get logs
 *
 * @param session session to use
 * @param unlogged_boot number of unlogged boots
 * @param unlogged_auth number of unlogged authentications
 * @param out array of log entries
 * @param n_items number of items in out
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_get_logs(yc_session *session, uint16_t *unlogged_boot,
                       uint16_t *unlogged_auth,
                       yc_log_entry out[YC_MAX_LOG_ENTRIES], uint16_t *n_items);

/**
 * Set the log index
 *
 * @param session session to use
 * @param index index to set
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_set_log_index(yc_session *session, uint16_t index);

/**
 * Get opaque object
 *
 * @param session session to use
 * @param object_id Object ID
 * @param out data
 * @param out_len length of out
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_get_opaque(yc_session *session, uint16_t object_id, uint8_t *out,
                         uint16_t *out_len);

/**
 * Import opaque object
 *
 * @param session session to use
 * @param object_id Object ID
 * @param label label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities
 * @param algorithm algorithm
 * @param in object data
 * @param in_len length of in
 *
 * @return
 **/
yc_rc yc_util_import_opaque(yc_session *session, uint16_t *object_id,
                            const uint8_t *label, size_t label_len,
                            uint16_t domains,
                            const yc_capabilities *capabilities,
                            yc_algorithm algorithm, const uint8_t *in,
                            uint16_t in_len);

/**
 * SSH certify
 *
 * @param session session to use
 * @param key_id Key ID
 * @param template_id Template ID
 * @param sig_algo signature algorithm
 * @param in Certificate request
 * @param in_len length of in
 * @param out Signature
 * @param out_len length of out
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_ssh_certify(yc_session *session, uint16_t key_id,
                          uint16_t template_id, yc_algorithm sig_algo,
                          const uint8_t *in, uint16_t in_len, uint8_t *out,
                          uint16_t *out_len);

/**
 * Import authentication key
 *
 * @param session session to use
 * @param key_id Object ID
 * @param label label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities capabilities
 * @param delegated_capabilities delegated capabilities
 * @param password password to derive key from
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_import_authkey(yc_session *session, uint16_t *key_id,
                             const uint8_t *label, size_t label_len,
                             uint16_t domains,
                             const yc_capabilities *capabilities,
                             const yc_capabilities *delegated_capabilities,
                             const char *password);

/**
 * Get template
 *
 * @param session session to use
 * @param object_id Object ID
 * @param out data
 * @param out_len length of out
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_get_template(yc_session *session, uint16_t object_id,
                           uint8_t *out, uint16_t *out_len);

/**
 * Import template
 *
 * @param session session to use
 * @param object_id Object ID
 * @param label label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities capabilities
 * @param algorithm algorithm
 * @param in data
 * @param in_len length of in
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_import_template(yc_session *session, uint16_t *object_id,
                              const uint8_t *label, size_t label_len,
                              uint16_t domains,
                              const yc_capabilities *capabilities,
                              yc_algorithm algorithm, const uint8_t *in,
                              uint16_t in_len);

/**
 * Create OTP AEAD
 *
 * @param session session to use
 * @param key_id Object ID
 * @param key OTP key
 * @param private_id OTP private id
 * @param out AEAD
 * @param out_len length of out
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_otp_aead_create(yc_session *session, uint16_t key_id,
                              const uint8_t *key, const uint8_t *private_id,
                              uint8_t *out, uint16_t *out_len);

/**
 * Create OTP AEAD from random
 *
 * @param session session to use
 * @param key_id Object ID
 * @param out AEAD
 * @param out_len length of out
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_otp_aead_random(yc_session *session, uint16_t key_id,
                              uint8_t *out, uint16_t *out_len);

/**
 * Decrypt OTP
 *
 * @param session session to use
 * @param key_id Object ID
 * @param aead AEAD
 * @param aead_len length of AEAD
 * @param otp OTP
 * @param useCtr OTP use counter
 * @param sessionCtr OTP session counter
 * @param tstph OTP timestamp high
 * @param tstpl OTP timestamp low
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_otp_decrypt(yc_session *session, uint16_t key_id,
                          const uint8_t *aead, uint16_t aead_len,
                          const uint8_t *otp, uint16_t *useCtr,
                          uint8_t *sessionCtr, uint8_t *tstph, uint16_t *tstpl);

/**
 * Import OTP AEAD Key
 *
 * @param session session to use
 * @param key_id Object ID
 * @param label label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities capabilities
 * @param nonce_id nonce ID
 * @param in key
 * @param in_len length of in
 *
 * @return
 **/
yc_rc yc_util_put_otp_aead_key(yc_session *session, uint16_t *key_id,
                               const uint8_t *label, size_t label_len,
                               uint16_t domains,
                               const yc_capabilities *capabilities,
                               uint32_t nonce_id, const uint8_t *in,
                               uint16_t in_len);

/**
 * Generate OTP AEAD Key
 *
 * @param session session to use
 * @param key_id Object ID
 * @param label label
 * @param label_len length of label
 * @param domains domains
 * @param capabilities capabilities
 * @param algorithm algorithm
 * @param nonce_id nonce ID
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_generate_otp_aead_key(yc_session *session, uint16_t *key_id,
                                    const uint8_t *label, size_t label_len,
                                    uint16_t domains,
                                    const yc_capabilities *capabilities,
                                    yc_algorithm algorithm, uint32_t nonce_id);

/**
 * Attest asymmetric key
 *
 * @param session session to use
 * @param key_id Object ID
 * @param attest_id Attestation key ID
 * @param out Certificate
 * @param out_len length of out
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_attest_asymmetric(yc_session *session, uint16_t key_id,
                                uint16_t attest_id, uint8_t *out,
                                uint16_t *out_len);

/**
 * Put global option
 *
 * @param session session to use
 * @param option option
 * @param len length of option data
 * @param val option data
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_put_option(yc_session *session, yc_option option, uint16_t len,
                         uint8_t *val);

/**
 * Get global option
 *
 * @param session session to use
 * @param option option
 * @param out option data
 * @param out_len length of out
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_get_option(yc_session *session, yc_option option, uint8_t *out,
                         uint16_t *out_len);

/**
 * Get storage statistics
 *
 * @param session session to use
 * @param total_records total records available
 * @param free_records number of free records
 * @param total_pages total pages available
 * @param free_pages number of free pages
 * @param page_size page size in bytes
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_get_storage_stats(yc_session *session, uint16_t *total_records,
                                uint16_t *free_records, uint16_t *total_pages,
                                uint16_t *free_pages, uint16_t *page_size);

/**
 * Wrap data
 *
 * @param session session to use
 * @param key_id Object ID
 * @param in data to wrap
 * @param in_len length of in
 * @param out wrapped data
 * @param out_len length of out
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_wrap_data(yc_session *session, uint16_t key_id, uint8_t *in,
                        uint16_t in_len, uint8_t *out, uint16_t *out_len);

/**
 * Unwrap data
 *
 * @param session session to use
 * @param key_id Object ID
 * @param in wrapped data
 * @param in_len length of in
 * @param out unwrapped data
 * @param out_len length of out
 *
 * @return yc_rc error code
 **/
yc_rc yc_util_unwrap_data(yc_session *session, uint16_t key_id, uint8_t *in,
                          uint16_t in_len, uint8_t *out, uint16_t *out_len);

/**
 * Get session ID
 *
 * @param session session to use
 * @param sid session ID
 *
 * @return yc_rc error code
 **/
yc_rc yc_get_session_id(yc_session *session, uint8_t *sid);

/**
 * Check if the connector has a device connected
 *
 * @param connector connector
 *
 * @return true or false
 **/
bool yc_connector_has_device(yc_connector *connector);

/**
 * Get the connector version
 *
 * @param connector connector
 * @param major major version
 * @param minor minor version
 * @param patch patch version
 *
 * @return yc_rc error code
 **/
yc_rc yc_get_connector_version(yc_connector *connector, uint8_t *major,
                               uint8_t *minor, uint8_t *patch);

/**
 * Get connector address
 *
 * @param connector connector
 * @param address pointer to string address
 *
 * @return yc_rc error code
 **/
yc_rc yc_get_connector_address(yc_connector *connector, char **const address);

/**
 * Convert capability string to byte array
 *
 * @param capability string of capabilities
 * @param result capabilities
 *
 * @return yc_rc error code
 **/
yc_rc yc_capabilities_to_num(const char *capability, yc_capabilities *result);

/**
 * Convert capability byte array to strings
 *
 * @param num capabilities
 * @param result array of string pointers
 * @param n_result number of elements of result
 *
 * @return yc_rc error code
 **/
yc_rc yc_num_to_capabilities(const yc_capabilities *num, const char *result[],
                             size_t *n_result);

/**
 * Check if capability is set
 *
 * @param capabilities capabilities
 * @param capability capability string
 *
 * @return true or false
 **/
bool yc_check_capability(const yc_capabilities *capabilities,
                         const char *capability);

/**
 * Check if algorithm is an RSA algorithm
 *
 * @param algorithm algorithm
 *
 * @return true or false
 **/
bool yc_is_rsa(yc_algorithm algorithm);

/**
 * Check if algorithm is an EC algorithm
 *
 * @param algorithm algorithm
 *
 * @return true or false
 **/
bool yc_is_ec(yc_algorithm algorithm);

/**
 * Check if algorithm is a HMAC algorithm
 *
 * @param algorithm algorithm
 *
 * @return true or false
 **/
bool yc_is_hmac(yc_algorithm algorithm);

/**
 * Get algorithm bitlength
 *
 * @param algorithm algorithm
 * @param result bitlength
 *
 * @return yc_rc error code
 **/
yc_rc yc_get_key_bitlength(yc_algorithm algorithm, uint16_t *result);

/**
 * Convert algorithm to string
 *
 * @param algo algorithm
 * @param result string
 *
 * @return yc_rc error code
 **/
yc_rc yc_algo_to_string(yc_algorithm algo, char const **result);

/**
 * Convert string to algorithm
 *
 * @param string algorithm as string
 * @param algo algorithm
 *
 * @return yc_rc error code
 **/
yc_rc yc_string_to_algo(const char *string, yc_algorithm *algo);

/**
 * Convert type to string
 *
 * @param type type
 * @param result string
 *
 * @return yc_rc error code
 **/
yc_rc yc_type_to_string(yc_object_type type, char const **result);

/**
 * Convert string to type
 *
 * @param string type as string
 * @param type type
 *
 * @return yc_rc error code
 **/
yc_rc yc_string_to_type(const char *string, yc_object_type *type);

/**
 * Convert string to option
 *
 * @param string option as string
 * @param option option
 *
 * @return yc_rc error code
 **/
yc_rc yc_string_to_option(const char *string, yc_option *option);

#ifdef __cplusplus
}
#endif

#endif
