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

#ifndef VIRGIL_CRYPTO_HSM_YUBICO_H
#define VIRGIL_CRYPTO_HSM_YUBICO_H

#include <virgil/crypto/VirgilByteArray.h>

#include <virgil/crypto/hsm/VirgilHsmKeyInfo.h>
#include <virgil/crypto/hsm/yubico/VirgilHsmYubicoConfig.h>

#include <memory>

namespace virgil { namespace crypto { namespace hsm { namespace yubico {

class VirgilHsmYubico {
public:
    VirgilHsmYubico(VirgilHsmYubicoConfig config = {});

    void connect();

    void disconnect();

    bool isConnected();

    VirgilHsmKeyInfo getKeyInfo(const VirgilByteArray& privateKey);

    VirgilByteArray generateKey(VirgilKeyPair::Algorithm keyAlgorithm);

    VirgilByteArray generateRecommendedKey();

    VirgilByteArray extractPublicKey(const VirgilByteArray& privateKey);

    void deleteKey(const VirgilByteArray& privateKey);

    VirgilByteArray exportPublicKey(const VirgilByteArray& privateKey);

    VirgilByteArray processRSA(const VirgilByteArray& data, const VirgilByteArray& privateKey);

    VirgilByteArray processECDH(const VirgilByteArray& publicKey, const VirgilByteArray& privateKey);

    VirgilByteArray signHash(const VirgilByteArray& digest, const VirgilByteArray& privateKey);

    VirgilHsmYubico(const VirgilHsmYubico&);

    VirgilHsmYubico(VirgilHsmYubico&&) noexcept;

    VirgilHsmYubico& operator=(const VirgilHsmYubico&);

    VirgilHsmYubico& operator=(VirgilHsmYubico&&) noexcept;

    ~VirgilHsmYubico() noexcept;

private:
    class KeyInfo;
    class Session;

    void establishConnection();

    VirgilByteArray wrapKey(uint16_t keyId) const;

    uint16_t unwrapKey(const VirgilByteArray& wrappedPrivateKey) const;

    bool getKeyInfo(const Session& session, uint16_t objectId, KeyInfo* keyInfo) const;

    bool isKeyEC(const KeyInfo& keyInfo) const;

    bool isKeyRSA(const KeyInfo& keyInfo) const;

private:
    class Impl;

    std::unique_ptr<Impl> impl_;
};

}}}}


#endif //VIRGIL_CRYPTO_HSM_YUBICO_H
