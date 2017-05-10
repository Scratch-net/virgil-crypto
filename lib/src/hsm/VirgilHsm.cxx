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

#include <virgil/crypto/hsm/VirgilHsm.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilKeyPair;

using virgil::crypto::foundation::VirgilHash;

using virgil::crypto::hsm::VirgilHsm;
using virgil::crypto::hsm::VirgilHsmKeyInfo;

VirgilHsmKeyInfo VirgilHsm::getKeyInfo(const VirgilByteArray& privateKey) const {
    return doGetKeyInfo(unwrapKey(privateKey));
}

VirgilByteArray VirgilHsm::generateKey(VirgilKeyPair::Algorithm keyAlgorithm) {
    return wrapKey(doGenerateKey(keyAlgorithm));
}

VirgilByteArray VirgilHsm::generateRecommendedKey() {
    return wrapKey(doGenerateRecommendedKey());
}

VirgilByteArray VirgilHsm::extractPublicKey(const VirgilByteArray& privateKey) const {
    return doExtractPublicKey(unwrapKey(privateKey));
}

void VirgilHsm::deleteKey(const VirgilByteArray& privateKey) {
    doDeleteKey(privateKey);
}

VirgilByteArray VirgilHsm::exportPublicKey(const VirgilByteArray& privateKey) const {
    return doExportPublicKey(unwrapKey(privateKey));
}

VirgilByteArray VirgilHsm::processRSA(const VirgilByteArray& data, const VirgilByteArray& privateKey) const {
    return doProcessRSA(data, unwrapKey(privateKey));
}

VirgilByteArray VirgilHsm::processECDH(const VirgilByteArray& publicKey, const VirgilByteArray& privateKey) const {
    return doProcessECDH(publicKey, unwrapKey(privateKey));
}

VirgilByteArray VirgilHsm::signHash(const VirgilByteArray& digest, const VirgilByteArray& privateKey) const {
    return doSignHash(digest, unwrapKey(privateKey));
}

VirgilByteArray VirgilHsm::wrapKey(const VirgilByteArray& privateKey) const {
    return privateKey;
}

VirgilByteArray VirgilHsm::unwrapKey(const VirgilByteArray& wrappedPrivateKey) const {
    return wrappedPrivateKey;
}
