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
 * @file test_hsm_cipher.cxx
 * @brief Covers class VirgilHsmCipher
 */

#include <catch.hpp>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/hsm/VirgilHsmCipher.h>
#include <virgil/crypto/hsm/yubico/VirgilHsmYubico.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::hsm::VirgilHsmCipher;
using virgil::crypto::hsm::yubico::VirgilHsmYubico;
using virgil::crypto::hsm::yubico::VirgilHsmYubicoConfig;


TEST_CASE("EncryptAndDecryptWithGeneratedKeys_EC_SECP256R1", "[hsm-cipher-yubico]") {


    auto hsm = VirgilHsmYubico();
    VirgilByteArray dataToEncrypt = VirgilByteArrayUtils::stringToBytes("this is a secret");
    VirgilByteArray aliceId = VirgilByteArrayUtils::stringToBytes("alice");
    VirgilByteArray alicePrivateKey = hsm.generateKey(VirgilKeyPair::Algorithm::EC_SECP256R1);
    VirgilByteArray alicePublicKey = hsm.exportPublicKey(alicePrivateKey);

    VirgilHsmCipher cipher(hsm);
    cipher.addKeyRecipient(aliceId, alicePublicKey);

    VirgilByteArray encryptedData;
    CHECK_NOTHROW(encryptedData = cipher.encrypt(dataToEncrypt));
    CHECK(!encryptedData.empty());

    VirgilByteArray decryptedData;
    CHECK_NOTHROW(decryptedData = cipher.decryptWithKey(encryptedData, aliceId, alicePrivateKey));

    CHECK(dataToEncrypt == decryptedData);

    hsm.deleteKey(alicePrivateKey);
}
