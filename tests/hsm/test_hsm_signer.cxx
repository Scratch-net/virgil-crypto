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
 * @file test_hsm_signer.cxx
 * @brief Covers class VirgilHsmSigner
 */

#include <catch.hpp>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/hsm/VirgilHsmSigner.h>
#include <virgil/crypto/hsm/yubico/VirgilHsmYubico.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::hsm::VirgilHsmSigner;
using virgil::crypto::hsm::yubico::VirgilHsmYubico;

static constexpr const char kYubicoConnectorUrl[] = "http://127.0.0.1:12345";

TEST_CASE("SignAndVerifyWithGeneratedKeys_EC_SECP256R1", "[hsm-signer-yubico]") {

    auto hsm = std::make_shared<VirgilHsmYubico>();
    hsm->connect(kYubicoConnectorUrl);
    VirgilByteArray dataToSigned = VirgilByteArrayUtils::stringToBytes("this is a secret");
    VirgilByteArray alicePrivateKey = hsm->generateKey(VirgilKeyPair::Algorithm::EC_SECP256R1);
    VirgilByteArray alicePublicKey = hsm->exportPublicKey(alicePrivateKey);

    VirgilHsmSigner signer(hsm);

    VirgilByteArray signature;
    CHECK_NOTHROW(signature = signer.sign(dataToSigned, alicePrivateKey));
    CHECK(!signature.empty());

    bool isVerified { false };
    CHECK_NOTHROW(isVerified = signer.verify(dataToSigned, signature, alicePublicKey));

    CHECK(isVerified);

    hsm->deleteKey(alicePrivateKey);
}
