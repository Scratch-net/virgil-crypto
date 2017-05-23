/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <virgil/crypto/hsm/VirgilHsmCipher.h>

#include <virgil/crypto/hsm/VirgilHsmKeyInfo.h>

#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/foundation/VirgilKeyHelper.h>

#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>

#include <mbedtls/ecies.h>
#include <mbedtls/ecies_internal.h>

#include <memory>
#include <cstring>

using virgil::crypto::VirgilCipher;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilCryptoError;
using virgil::crypto::VirgilCryptoException;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::make_error;

using virgil::crypto::hsm::VirgilHsm;
using virgil::crypto::hsm::VirgilHsmKeyInfo;
using virgil::crypto::hsm::VirgilHsmCipher;

using virgil::crypto::foundation::VirgilKeyHelper;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;


namespace internal {

struct KeyContext {
    VirgilKeyPair::Algorithm algorithm;
    VirgilByteArray key;
};

static void* hsm_key_alloc_wrap(void) {
    return new KeyContext();
}

static void hsm_key_free_wrap(void* key) {
    KeyContext* hsmKey = static_cast<KeyContext*>(key);
    if (hsmKey != nullptr) {
        VirgilByteArrayUtils::zeroize(hsmKey->key);
        delete hsmKey;
    }
}

static int hsm_key_compute_shared_wrap(
        void* pub, void* prv,
        unsigned char* shared, size_t shared_len,
        int (* f_rng)(void*, unsigned char*, size_t), void* p_rng) {
    (void) f_rng;
    (void) p_rng;

    VirgilHsm* hsm = static_cast<VirgilHsm*>(p_rng);
    const KeyContext* publicKey = static_cast<KeyContext*>(pub);
    const KeyContext* privateKey = static_cast<KeyContext*>(prv);

    VirgilByteArray result;
    try {
        result = hsm->processECDH(publicKey->key, privateKey->key);
    } catch (const std::exception&) {
        return MBEDTLS_ERR_ECIES_BAD_INPUT_DATA;
    }

    if (result.size() > shared_len) {
        return MBEDTLS_ERR_ECIES_OUTPUT_TOO_SMALL;
    }

    memcpy(shared, result.data(), result.size());

    return 0;
}

static size_t hsm_key_get_shared_len_wrap(void* key) {
    const KeyContext* keyContext = static_cast<KeyContext*>(key);
    try {
        return VirgilKeyHelper::getKeySize(keyContext->algorithm);
    } catch (const std::exception&) {
        //TODO: Log this when logging will be added.
        return 0;
    }
}

static int hsm_key_read_pub_asn1_wrap(unsigned char** p, const unsigned char* end, void* key) {

    KeyContext* publicKeyContext = static_cast<KeyContext*>(key);

    try {
        VirgilByteArray asn1(static_cast<const unsigned char*>(*p), end);
        VirgilAsn1Reader asn1Reader(asn1);
        VirgilByteArray keyStructure = asn1Reader.readData();
        auto publicKeyInfo = VirgilKeyHelper::readPublicKeyEC(keyStructure);
        publicKeyContext->algorithm = publicKeyInfo.algorithm;
        publicKeyContext->key = std::move(publicKeyInfo.key);
        *p += keyStructure.size();
    } catch (const std::exception&) {
        return MBEDTLS_ERR_ECIES_BAD_INPUT_DATA;
    }

    return 0;
}

const mbedtls_ecies_info_t ecies_hsm_info = {
        MBEDTLS_ECIES_ECP, // type
        "ECIES_HSM_EC", // name
        hsm_key_alloc_wrap, // key_alloc_func
        hsm_key_free_wrap, // key_free_func
        nullptr, // key_gen_ephemeral_func
        hsm_key_compute_shared_wrap, // key_make_shared_func
        hsm_key_get_shared_len_wrap, // key_get_shared_len_func
        nullptr, // key_write_pub_asn1_func
        hsm_key_read_pub_asn1_wrap, // key_read_pub_asn1_func
};

} //internal

VirgilHsmCipher::VirgilHsmCipher(VirgilHsm hsm) : hsm_(std::move(hsm)) {
}

VirgilByteArray VirgilHsmCipher::doDecryptWithKey(
        const VirgilByteArray& algorithm, const VirgilByteArray& encryptedKey,
        const VirgilByteArray& privateKey, const VirgilByteArray&) {

    if (!hsm_.isConnected()) {
        hsm_.connect();
    }

    auto keyAlgorithm = VirgilKeyHelper::readAlgorithm(algorithm, encryptedKey.size());

    if (VirgilKeyHelper::isRSA(keyAlgorithm)) {
        return hsm_.processRSA(encryptedKey, privateKey);
    }

    if (VirgilKeyHelper::isEC(keyAlgorithm)) {
        return eciesDecrypt(encryptedKey, privateKey);
    }

    throw make_error(VirgilCryptoError::InvalidState, "Algorithm not detected.");
}


VirgilByteArray VirgilHsmCipher::eciesDecrypt(
        const VirgilByteArray& encryptedKey, const VirgilByteArray& privateKey) {

    auto keyInfo = hsm_.getKeyInfo(privateKey);

    internal::KeyContext keyContext;
    keyContext.key = privateKey;
    keyContext.algorithm = keyInfo.algorithm;

    size_t resultSize = 512;
    VirgilByteArray result(resultSize);
    foundation::system_crypto_handler(mbedtls_ecies_decrypt(
            &keyContext, &internal::ecies_hsm_info,
            VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(encryptedKey), result.data(), &resultSize, resultSize, nullptr, &hsm_));

    result.resize(resultSize);

    return result;
}
