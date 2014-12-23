/**
 * Copyright (C) 2014 Virgil Security Inc.
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

#ifndef VIRGIL_SERVICE_STREAM_VIRGIL_STREAM_CIPHER_H
#define VIRGIL_SERVICE_STREAM_VIRGIL_STREAM_CIPHER_H

#include <virgil/service/VirgilCipherBase.h>
using virgil::service::VirgilCipherBase;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <virgil/service/stream/VirgilDataSource.h>
using virgil::service::stream::VirgilDataSource;

#include <virgil/service/stream/VirgilDataSink.h>
using virgil::service::stream::VirgilDataSink;

namespace virgil { namespace service { namespace stream {

/**
 * @brief This class provides high-level interface to encrypt / decrypt streaming data using Virgil Security keys.
 */
class VirgilStreamCipher : public VirgilCipherBase {
public:
    /**
     * @brief Polymorphic destructor.
     */
    virtual ~VirgilStreamCipher() throw();
public:
    /**
     * @brief Encrypt data read from given source with public key and write it the sink.
     * @return encryption key - key that was used for symmetric encryption,
     *             and was encrypted by public key for security transfer via public networks.
     * @note Encryption key is used for data decryption in conjuction with private key.
     */
    VirgilByteArray encrypt(VirgilDataSource& source, VirgilDataSink& sink,
            const VirgilByteArray& publicKey);
    /**
     * @brief Decrypt data read from given source with given private key and write it to the sink.
     */
    void decrypt(VirgilDataSource& source, VirgilDataSink& sink, const VirgilByteArray& encryptionKey,
            const VirgilByteArray& privateKey, const VirgilByteArray& privateKeyPassword = VirgilByteArray());
    /**
     * @brief Encrypt plain text with given password.
     * @return Encrypted data.
     */
    void encryptWithPassword(VirgilDataSource& source, VirgilDataSink& sink, const VirgilByteArray& pwd);
    /**
     * @brief Decrypt data with given password.
     * @return Plain text.
     */
    void decryptWithPassword(VirgilDataSource& source, VirgilDataSink& sink, const VirgilByteArray& pwd);
};

}}}

#endif /* VIRGIL_SERVICE_STREAM_VIRGIL_STREAM_CIPHER_H */