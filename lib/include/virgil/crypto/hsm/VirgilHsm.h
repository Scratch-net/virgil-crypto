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

#ifndef VIRGIL_CRYPTO_HSM_H
#define VIRGIL_CRYPTO_HSM_H

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilKeyPair.h>
#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/hsm/VirgilHsmKeyInfo.h>

#include <memory>

namespace virgil { namespace crypto { namespace hsm {

class VirgilHsm {
private:
    template<typename T>
    class VirgilHsmImpl;

public:
    template<typename T>
    VirgilHsm(T hsm) : self_(new VirgilHsmImpl<T>(std::move(hsm))) {
    }

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

public:
    VirgilHsm(const VirgilHsm& other);

    VirgilHsm(VirgilHsm&& other) noexcept = default;

    VirgilHsm& operator=(const VirgilHsm& other);

    VirgilHsm& operator=(VirgilHsm&& other) noexcept = default;

    ~VirgilHsm() noexcept = default;

private:
    struct VirgilHsmInterface {
        virtual void doConnect() = 0;

        virtual void doDisconnect() = 0;

        virtual bool doIsConnected() = 0;

        virtual VirgilHsmKeyInfo doGetKeyInfo(const VirgilByteArray& privateKey) = 0;

        virtual VirgilByteArray doGenerateKey(VirgilKeyPair::Algorithm keyAlgorithm) = 0;

        virtual VirgilByteArray doGenerateRecommendedKey() = 0;

        virtual VirgilByteArray doExtractPublicKey(const VirgilByteArray& privateKey) = 0;

        virtual void doDeleteKey(const VirgilByteArray& privateKey) = 0;

        virtual VirgilByteArray doExportPublicKey(const VirgilByteArray& privateKey) = 0;

        virtual VirgilByteArray doProcessRSA(const VirgilByteArray& data, const VirgilByteArray& privateKey) = 0;

        virtual VirgilByteArray doProcessECDH(const VirgilByteArray& publicKey, const VirgilByteArray& privateKey) = 0;

        virtual VirgilByteArray doSignHash(const VirgilByteArray& digest, const VirgilByteArray& privateKey) = 0;

        virtual VirgilHsmInterface* doCopy() const = 0;
    };

    template<typename T>
    struct VirgilHsmImpl : VirgilHsmInterface {
        VirgilHsmImpl(T hsmImpl) : hsmImpl_(std::move(hsmImpl)) {}

        void doConnect() override {
            hsmImpl_.connect();
        }

        void doDisconnect() override {
            hsmImpl_.disconnect();
        }

        bool doIsConnected() override {
            return hsmImpl_.isConnected();
        }

        VirgilHsmKeyInfo doGetKeyInfo(const VirgilByteArray& privateKey) override {
            return hsmImpl_.getKeyInfo(privateKey);
        }

        VirgilByteArray doGenerateKey(VirgilKeyPair::Algorithm keyAlgorithm) override {
            return hsmImpl_.generateKey(keyAlgorithm);
        }

        VirgilByteArray doGenerateRecommendedKey() override {
            return hsmImpl_.generateRecommendedKey();
        }

        VirgilByteArray doExtractPublicKey(const VirgilByteArray& privateKey) override {
            return hsmImpl_.extractPublicKey(privateKey);
        }

        void doDeleteKey(const VirgilByteArray& privateKey) override {
            hsmImpl_.deleteKey(privateKey);
        }

        VirgilByteArray doExportPublicKey(const VirgilByteArray& privateKey) override {
            return hsmImpl_.exportPublicKey(privateKey);
        }

        VirgilByteArray doProcessRSA(const VirgilByteArray& data, const VirgilByteArray& privateKey) override {
            return hsmImpl_.processRSA(data, privateKey);
        }

        VirgilByteArray doProcessECDH(const VirgilByteArray& publicKey, const VirgilByteArray& privateKey) override {
            return hsmImpl_.processECDH(publicKey, privateKey);
        }

        VirgilByteArray doSignHash(const VirgilByteArray& digest, const VirgilByteArray& privateKey) override {
            return hsmImpl_.signHash(digest, privateKey);
        }

        VirgilHsmInterface* doCopy() const override {
            return new VirgilHsmImpl(*this);
        }
    private:
        T hsmImpl_;
    };

private:
    std::unique_ptr<VirgilHsmInterface> self_;
};

}}}

#endif //VIRGIL_CRYPTO_HSM_H
