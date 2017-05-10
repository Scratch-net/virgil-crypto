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

/**
 * @file test_hsm_yubico.cxx
 * @brief Covers class VirgilHsmYubico
 */

#include <catch.hpp>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/hsm/yubico/VirgilHsmYubico.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::foundation::VirgilHash;
using virgil::crypto::hsm::VirgilHsm;
using virgil::crypto::hsm::yubico::VirgilHsmYubico;

static constexpr const char kYubicoConnectorUrl[] = "http://127.0.0.1:12345";

TEST_CASE("EstablishConnectionWithValidUrl", "[hsm-yubico]") {
    auto hsm = std::make_shared<VirgilHsmYubico>();
    CHECK_NOTHROW(hsm->connect(kYubicoConnectorUrl));
    CHECK(hsm->isConnected());
    CHECK_NOTHROW(hsm->disconnect());
    CHECK_FALSE(hsm->isConnected());
}

TEST_CASE("GenerateAndRemoveKey", "[hsm-yubico]") {
    auto hsm = std::make_shared<VirgilHsmYubico>();
    hsm->connect(kYubicoConnectorUrl);
    VirgilByteArray privateKey;
    CHECK_NOTHROW(privateKey = hsm->generateRecommendedKey());
    CHECK_NOTHROW(hsm->deleteKey(privateKey));
}

TEST_CASE("ExportPublicKeyFromFakePrivateKey", "[hsm-yubico]") {
    auto hsm = std::make_shared<VirgilHsmYubico>();
    hsm->connect(kYubicoConnectorUrl);
    VirgilByteArray privateKey = VirgilByteArrayUtils::hexToBytes("300702010002024c39");
    VirgilByteArray publicKey;
    CHECK_THROWS(publicKey = hsm->exportPublicKey(privateKey));
}

TEST_CASE("ExportPublicKeyFromGeneratedPrivateKey", "[hsm-yubico]") {
    auto hsm = std::make_shared<VirgilHsmYubico>();
    hsm->connect(kYubicoConnectorUrl);
    VirgilByteArray privateKey = hsm->generateRecommendedKey();
    VirgilByteArray publicKey;
    CHECK_NOTHROW(publicKey = hsm->exportPublicKey(privateKey));
    hsm->deleteKey(privateKey);
}

TEST_CASE("ExportPublicKeyFromGeneratedPrivateKey_RSA_2048", "[hsm-yubico]") {
    auto hsm = std::make_shared<VirgilHsmYubico>();
    hsm->connect(kYubicoConnectorUrl);
    VirgilByteArray privateKey = hsm->generateKey(VirgilKeyPair::Algorithm::RSA_2048);
    VirgilByteArray publicKey;
    CHECK_NOTHROW(publicKey = hsm->exportPublicKey(privateKey));
    hsm->deleteKey(privateKey);
}

TEST_CASE("ExportPublicKeyFromGeneratedPrivateKey_EC_SECP256R1", "[hsm-yubico]") {
    auto hsm = std::make_shared<VirgilHsmYubico>();
    hsm->connect(kYubicoConnectorUrl);
    VirgilByteArray privateKey = hsm->generateKey(VirgilKeyPair::Algorithm::EC_SECP256R1);
    VirgilByteArray publicKey;
    CHECK_NOTHROW(publicKey = hsm->exportPublicKey(privateKey));
    hsm->deleteKey(privateKey);
}

TEST_CASE("ComputeSharedKeyFromGeneratedKeys_EC_SECP256R1", "[hsm-yubico]") {
    auto hsm = std::make_shared<VirgilHsmYubico>();
    hsm->connect(kYubicoConnectorUrl);
    VirgilByteArray alicePrivateKey = hsm->generateKey(VirgilKeyPair::Algorithm::EC_SECP256R1);
    VirgilByteArray alicePublicKey = hsm->extractPublicKey(alicePrivateKey);

    VirgilByteArray bobPrivateKey = hsm->generateKey(VirgilKeyPair::Algorithm::EC_SECP256R1);
    VirgilByteArray bobPublicKey = hsm->extractPublicKey(bobPrivateKey);

    VirgilByteArray aliceSharedKey;
    CHECK_NOTHROW(aliceSharedKey = hsm->processECDH(bobPublicKey, alicePrivateKey));
    CHECK_FALSE(aliceSharedKey.empty());

    VirgilByteArray bobSharedKey;
    CHECK_NOTHROW(bobSharedKey = hsm->processECDH(alicePublicKey, bobPrivateKey));
    CHECK_FALSE(bobSharedKey.empty());

    CHECK(VirgilByteArrayUtils::bytesToHex(aliceSharedKey) == VirgilByteArrayUtils::bytesToHex(bobSharedKey));

    hsm->deleteKey(alicePrivateKey);
    hsm->deleteKey(bobPrivateKey);
}

TEST_CASE("MakeSignatureWithGeneratedPrivateKey", "[hsm-yubico]") {
    auto hsm = std::make_shared<VirgilHsmYubico>();
    hsm->connect(kYubicoConnectorUrl);
    VirgilByteArray privateKey = hsm->generateKey(VirgilKeyPair::Algorithm::EC_SECP256R1);
    VirgilByteArray signature;
    VirgilHash hash(VirgilHash::Algorithm::SHA384);
    const auto data = VirgilByteArrayUtils::stringToBytes("hello");
    const auto digest = hash.hash(data);
    CHECK_NOTHROW(signature = hsm->signHash(digest, privateKey));
    hsm->deleteKey(privateKey);
}
