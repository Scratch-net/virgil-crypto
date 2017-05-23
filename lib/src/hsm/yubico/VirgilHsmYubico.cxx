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

#include <virgil/crypto/hsm/yubico/VirgilHsmYubico.h>


#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/VirgilKeyHelper.h>
#include <virgil/crypto/foundation/VirgilHash.h>

#include <virgil/crypto/VirgilCryptoError.h>
#include <virgil/crypto/internal/utils.h>

#include <virgil/crypto/hsm/VirgilHsmKeyInfo.h>
#include <virgil/crypto/hsm/yubico/VirgilHsmYubicoError.h>
#include <virgil/crypto/hsm/yubico/internal/VirgilYubicoResource.h>

#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <yubico/yubicrypt.h>

#include <mutex>
#include <memory>
#include <array>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::VirgilCryptoError;

using virgil::crypto::hsm::VirgilHsmKeyInfo;
using virgil::crypto::hsm::yubico::VirgilHsmYubico;
using virgil::crypto::hsm::yubico::VirgilHsmYubicoConfig;

using virgil::crypto::foundation::VirgilKeyHelper;
using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

/*
 * Internal structures
 */
namespace virgil { namespace crypto { namespace hsm { namespace yubico {

struct VirgilHsmYubico::Impl {
    Impl(VirgilHsmYubicoConfig aConfig, internal::yubico_connector aConnector)
            : config(std::move(aConfig)), connector(std::move(aConnector)) {}

    VirgilHsmYubicoConfig config;
    internal::yubico_connector connector;
};

class VirgilHsmYubico::KeyInfo {
public:
    yc_object_descriptor ycObjectInfo = {};
};

class VirgilHsmYubico::Session {
public:
    explicit Session(internal::yubico_session* s) : p(s) {}

    internal::yubico_session* p{ nullptr };
};

}}}}

/*
 * Internal constants / variables
 */

namespace virgil { namespace crypto { namespace hsm { namespace yubico { namespace internal {

namespace global {

static size_t instances = { 0 };
static std::mutex instancesMutex;

static void hsm_increase_instances() {
    std::lock_guard<std::mutex> lockInstances(instancesMutex);
    if (instances == 0) {
        hsm_yubico_handler(yc_init());
        ++instances;
    }
}

static void hsm_decrease_instances() noexcept {
    std::lock_guard<std::mutex> lockInstances(instancesMutex);
    if (instances == 1) {
        hsm_yubico_handler(yc_exit(), [](int) {
            //TODO: Log this when logging will be added.
        });
        --instances;
    }
}

}

namespace serialize {

static constexpr const int version = 0;

}

static constexpr const size_t signatureLengthMax = 1024;

}}}}}

/*
 * Internal helpers
 */

namespace virgil { namespace crypto { namespace hsm { namespace yubico { namespace internal {

static yubico_session create_yubico_session(yc_connector* connector) {
    constexpr const int kMagicAuthKeysetId = 1;
    auto session = internal::make_yubico_session();
    uint8_t context[YC_CONTEXT_LEN];

    hsm_yubico_handler(session.create(connector, kMagicAuthKeysetId, YC_DEFAULT_PASSWORD, context));
    hsm_yubico_handler(session.apply(yc_authenticate_session, context));

    return session;
}

static VirgilKeyPair::Algorithm from_yubico_algorithm(yc_algorithm algorithm) {
    switch (algorithm) {
        case YC_ALGO_RSA_2048:
            return VirgilKeyPair::Algorithm::RSA_2048;
        case YC_ALGO_RSA_3072:
            return VirgilKeyPair::Algorithm::RSA_3072;
        case YC_ALGO_RSA_4096:
            return VirgilKeyPair::Algorithm::RSA_4096;
        case YC_ALGO_EC_P256:
            return VirgilKeyPair::Algorithm::EC_SECP256R1;
        case YC_ALGO_EC_P384:
            return VirgilKeyPair::Algorithm::EC_SECP384R1;
        case YC_ALGO_EC_P521:
            return VirgilKeyPair::Algorithm::EC_SECP521R1;
        case YC_ALGO_EC_K256:
            return VirgilKeyPair::Algorithm::EC_SECP256K1;
        case YC_ALGO_EC_BP256:
            return VirgilKeyPair::Algorithm::EC_BP256R1;
        case YC_ALGO_EC_BP384:
            return VirgilKeyPair::Algorithm::EC_BP384R1;
        case YC_ALGO_EC_BP512:
            return VirgilKeyPair::Algorithm::EC_BP512R1;
        default:
            throw make_error(VirgilHsmError::UnsupportedAlgorithm);
    }
}

static yc_algorithm to_yubico_algorithm(VirgilKeyPair::Algorithm algorithm) {
    switch (algorithm) {
        case VirgilKeyPair::Algorithm::RSA_2048:
            return YC_ALGO_RSA_2048;
        case VirgilKeyPair::Algorithm::RSA_3072:
            return YC_ALGO_RSA_3072;
        case VirgilKeyPair::Algorithm::RSA_4096:
            return YC_ALGO_RSA_4096;
        case VirgilKeyPair::Algorithm::EC_SECP256R1:
            return YC_ALGO_EC_P256;
        case VirgilKeyPair::Algorithm::EC_SECP384R1:
            return YC_ALGO_EC_P384;
        case VirgilKeyPair::Algorithm::EC_SECP521R1:
            return YC_ALGO_EC_P521;
        case VirgilKeyPair::Algorithm::EC_SECP256K1:
            return YC_ALGO_EC_K256;
        case VirgilKeyPair::Algorithm::EC_BP256R1:
            return YC_ALGO_EC_BP256;
        case VirgilKeyPair::Algorithm::EC_BP384R1:
            return YC_ALGO_EC_BP384;
        case VirgilKeyPair::Algorithm::EC_BP512R1:
            return YC_ALGO_EC_BP512;
        default:
            throw make_error(VirgilHsmError::UnsupportedAlgorithm);
    }
}

}}}}}

VirgilHsmYubico::VirgilHsmYubico(VirgilHsmYubicoConfig config)
        : impl_(std::make_unique<Impl>(std::move(config), internal::make_yubico_connector())) {
    internal::global::hsm_increase_instances();
}

VirgilHsmYubico::~VirgilHsmYubico() noexcept {
    internal::global::hsm_decrease_instances();
}

VirgilHsmYubico::VirgilHsmYubico(const VirgilHsmYubico& other)
        : impl_(std::make_unique<Impl>(other.impl_->config, internal::make_yubico_connector())) {
    internal::global::hsm_increase_instances();
}

VirgilHsmYubico& VirgilHsmYubico::operator=(const VirgilHsmYubico& other) {
    VirgilHsmYubico tmp(other.impl_->config);
    *this = std::move(tmp);
    internal::global::hsm_increase_instances();
    return *this;
}

VirgilHsmYubico& VirgilHsmYubico::operator=(VirgilHsmYubico&&) noexcept = default;

VirgilHsmYubico::VirgilHsmYubico(VirgilHsmYubico&&) noexcept = default;

void VirgilHsmYubico::connect() {
    if (isConnected()) {
        throw make_error(VirgilHsmError::InvalidParams, "Connection already established.");
    }
    auto connectorUrl = impl_->config.getConnectorUrl();
    char* url = const_cast<char*>(connectorUrl.c_str());
    hsm_yubico_handler(impl_->connector.create(&url, 1));
}

void VirgilHsmYubico::disconnect() {
    hsm_yubico_handler(impl_->connector.destroy(), [](int) {
        //TODO: Log this when logging will be added.
    });
}

bool VirgilHsmYubico::isConnected() {
    return impl_->connector.isAlive();
}

VirgilHsmKeyInfo VirgilHsmYubico::getKeyInfo(const VirgilByteArray& privateKey) {
    establishConnection();
    auto session = internal::create_yubico_session(impl_->connector.get());
    uint16_t keyId = unwrapKey(privateKey);

    KeyInfo keyInfo;
    if (!getKeyInfo(Session(&session), keyId, &keyInfo)) {
        throw make_error(VirgilHsmError::DeviceObjNotFound, "Given key is not found.");
    }

    return { internal::from_yubico_algorithm(keyInfo.ycObjectInfo.algorithm) };
}

VirgilByteArray VirgilHsmYubico::generateKey(VirgilKeyPair::Algorithm keyAlgorithm) {
    establishConnection();
    auto session = internal::create_yubico_session(impl_->connector.get());
    uint16_t keyId{ 0 };
    uint16_t domains = 16;
    uint8_t keyLabel[YC_OBJ_LABEL_LEN] = "virgil-private-key";
    yc_capabilities capabilities = {{ 0 }};

    auto ycKeyAlgorithm = internal::to_yubico_algorithm(keyAlgorithm);

    if (VirgilKeyHelper::isRSA(keyAlgorithm)) {
        hsm_yubico_handler(yc_capabilities_to_num("asymmetric_sign_pkcs:asymmetric_decrypt_pkcs", &capabilities));
        hsm_yubico_handler(yc_util_generate_key_rsa(
                session.get(), &keyId, keyLabel, sizeof(keyLabel), domains, &capabilities, ycKeyAlgorithm)
        );
    } else if (VirgilKeyHelper::isEC(keyAlgorithm)) {
        hsm_yubico_handler(yc_capabilities_to_num("asymmetric_sign_ecdsa:asymmetric_decrypt_ecdh", &capabilities));
        hsm_yubico_handler(yc_util_generate_key_ec(
                session.get(), &keyId, keyLabel, sizeof(keyLabel), domains, &capabilities, ycKeyAlgorithm)
        );
    } else {
        throw make_error(VirgilHsmError::UnsupportedAlgorithm, "Unsupported key algorithm.");
    }

    return wrapKey(keyId);
}

VirgilByteArray VirgilHsmYubico::generateRecommendedKey() {
    return generateKey(VirgilKeyPair::Algorithm::EC_SECP256R1);
}

VirgilByteArray VirgilHsmYubico::extractPublicKey(const VirgilByteArray& privateKey) {
    establishConnection();
    auto session = internal::create_yubico_session(impl_->connector.get());
    const auto keyId = unwrapKey(privateKey);
    std::array<uint8_t, 1024> ecPoint;
    uint16_t rawPublicKeySize = static_cast<uint16_t>(ecPoint.size());
    yc_algorithm ycAlgorithm;
    hsm_yubico_handler(yc_util_get_pubkey(
            session.get(), keyId, ecPoint.data(), &rawPublicKeySize, &ycAlgorithm
    ));
    return VirgilKeyHelper::ecPointToOctetString(VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(ecPoint.data(), rawPublicKeySize));
}

void VirgilHsmYubico::deleteKey(const VirgilByteArray& privateKey) {
    establishConnection();
    auto session = internal::create_yubico_session(impl_->connector.get());
    const auto keyId = unwrapKey(privateKey);
    hsm_yubico_handler(yc_util_delete_object(session.get(), YC_ASYMMETRIC, keyId));
}

VirgilByteArray VirgilHsmYubico::exportPublicKey(const VirgilByteArray& privateKey) {
    // Get public key info
    establishConnection();
    auto session = internal::create_yubico_session(impl_->connector.get());
    const auto keyId = unwrapKey(privateKey);
    std::array<uint8_t, 1024> rawPublicKey;
    uint16_t rawPublicKeySize = static_cast<uint16_t>(rawPublicKey.size());
    yc_algorithm ycAlgorithm;
    hsm_yubico_handler(yc_util_get_pubkey(
            session.get(), keyId, rawPublicKey.data(), &rawPublicKeySize, &ycAlgorithm
    ));
    // Convert to the SubjectPublicKeyInfo structure
    auto key = VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(rawPublicKey.data(), rawPublicKeySize);
    auto keyAlgorithm = internal::from_yubico_algorithm(ycAlgorithm);
    if (VirgilKeyHelper::isRSA(keyAlgorithm)) {
        constexpr const int publicExponent = 65537;
        return VirgilKeyHelper::writePublicKeyRSA(keyAlgorithm, key, publicExponent);
    }
    if (VirgilKeyHelper::isEC(keyAlgorithm)) {
        return VirgilKeyHelper::writePublicKeyEC(keyAlgorithm, VirgilKeyHelper::ecPointToOctetString(key));
    }
    throw make_error(VirgilCryptoError::InvalidState);
}

VirgilByteArray VirgilHsmYubico::processRSA(const VirgilByteArray& data, const VirgilByteArray& privateKey) {
    establishConnection();
    auto session = internal::create_yubico_session(impl_->connector.get());
    uint16_t keyId = unwrapKey(privateKey);

    uint16_t resultSize = 1024;
    VirgilByteArray result(resultSize);

    hsm_yubico_handler(session.apply(
            yc_util_decrypt_pkcs1v1_5, keyId, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(data), result.data(), &resultSize
    ));

    result.resize(resultSize);

    return result;
}

VirgilByteArray VirgilHsmYubico::processECDH(const VirgilByteArray& publicKey, const VirgilByteArray& privateKey) {
    establishConnection();
    auto session = internal::create_yubico_session(impl_->connector.get());
    uint16_t keyId = unwrapKey(privateKey);

    const auto ecPoint = VirgilKeyHelper::octetStringToECPoint(publicKey);
    const auto fieldElementSize = ecPoint.size() >> 1;
    uint16_t resultSize = static_cast<uint16_t>(fieldElementSize);
    VirgilByteArray result(resultSize);

    hsm_yubico_handler(session.apply(
            yc_util_decrypt_ecdh, keyId, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(publicKey), result.data(), &resultSize
    ));

    result.resize(resultSize);
    return result;
}

VirgilByteArray VirgilHsmYubico::signHash(const VirgilByteArray& digest, const VirgilByteArray& privateKey) {
    establishConnection();
    auto session = internal::create_yubico_session(impl_->connector.get());
    uint16_t keyId = unwrapKey(privateKey);

    KeyInfo keyInfo;
    if (!getKeyInfo(Session(&session), keyId, &keyInfo)) {
        throw make_error(VirgilHsmError::DeviceObjNotFound, "Given key is not found.");
    }

    uint8_t sign[internal::signatureLengthMax] = { 0 };
    uint16_t signLength = internal::signatureLengthMax;

    if (isKeyRSA(keyInfo)) {
        hsm_yubico_handler(session.apply(
                yc_util_sign_pkcs1v1_5, keyId, true, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(digest), sign, &signLength
        ));
    } else if (isKeyEC(keyInfo)) {
        auto keySize = VirgilKeyHelper::getKeySize(internal::from_yubico_algorithm(keyInfo.ycObjectInfo.algorithm));
        auto derivedDigest = VirgilKeyHelper::ecDeriveIntegerFromHash(digest, keySize);
        hsm_yubico_handler(session.apply(
                yc_util_sign_ecdsa, keyId, VIRGIL_BYTE_ARRAY_TO_PTR_AND_LEN(derivedDigest), sign, &signLength
        ));
    } else {
        throw make_error(VirgilCryptoError::InvalidState, __FUNCTION__);
    }
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(sign, signLength);
}

void VirgilHsmYubico::establishConnection() {
    if (!isConnected()) {
        connect();
    }
}

VirgilByteArray VirgilHsmYubico::wrapKey(uint16_t keyId) const {
    VirgilAsn1Writer asn1Writer;
    size_t len{ 0 };
    len += asn1Writer.writeInteger(static_cast<int>(keyId));
    len += asn1Writer.writeInteger(internal::serialize::version);
    asn1Writer.writeSequence(len);
    return asn1Writer.finish();
}

uint16_t VirgilHsmYubico::unwrapKey(const VirgilByteArray& wrappedPrivateKey) const {
    VirgilAsn1Reader asn1Reader(wrappedPrivateKey);

    asn1Reader.readSequence();
    if (asn1Reader.readInteger() != internal::serialize::version) {
        throw make_error(VirgilHsmError::UnsupportedAlgorithm, "Unsupported private key format. Invalid version.");
    }
    int keyId = asn1Reader.readInteger();
    if (keyId < 0 || keyId > std::numeric_limits<uint16_t>::max()) {
        throw make_error(VirgilHsmError::InvalidParams, "Malformed private key. Key identifier is out of range.");
    }
    return static_cast<uint16_t>(keyId);
}

bool VirgilHsmYubico::getKeyInfo(
        const VirgilHsmYubico::Session& session, uint16_t objectId, VirgilHsmYubico::KeyInfo* keyInfo) const {
    bool found = false;
    hsm_yubico_handler(session.p->apply(
            yc_util_get_object_info, objectId, YC_ASYMMETRIC, &found, &keyInfo->ycObjectInfo));
    return found;
}

bool VirgilHsmYubico::isKeyEC(const KeyInfo& keyInfo) const {
    return VirgilKeyHelper::isEC(internal::from_yubico_algorithm(keyInfo.ycObjectInfo.algorithm));
}

bool VirgilHsmYubico::isKeyRSA(const KeyInfo& keyInfo) const {
    return VirgilKeyHelper::isRSA(internal::from_yubico_algorithm(keyInfo.ycObjectInfo.algorithm));
}
