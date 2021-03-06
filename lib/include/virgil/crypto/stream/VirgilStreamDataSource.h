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

#ifndef VIRGIL_CRYPTO_VIRGIL_STREAM_DATA_SOURCE_H
#define VIRGIL_CRYPTO_VIRGIL_STREAM_DATA_SOURCE_H

#include <istream>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilDataSource.h>

namespace virgil { namespace crypto { namespace stream {

/**
 * @brief C++ stream implementation of the VirgilDataSource class.
 *
 * @note This class CAN not be used in wrappers.
 */
class VirgilStreamDataSource : public virgil::crypto::VirgilDataSource {
public:
    /**
     * @brief Creates data sink based on std::istream object.
     * @param in - input stream.
     * @param chunkSize - size of the data that will be returned by @link read() @endlink method.
     *                    Note, the real value may be different from the given value, it is only recommendation.
     */
    explicit VirgilStreamDataSource(std::istream& in, size_t chunkSize = 4096);

    /**
     * @brief Polymorphic destructor.
     */
    virtual ~VirgilStreamDataSource() noexcept;

    /**
     * @brief Overriding of @link VirgilDataSource::hasData() @endlink method.
     */
    virtual bool hasData();

    /**
     * @brief Overriding of @link VirgilDataSource::read() @endlink method.
     */
    virtual virgil::crypto::VirgilByteArray read();

private:
    std::istream& in_;
    size_t chunkSize_;
};

}}}

#endif /* VIRGIL_CRYPTO_VIRGIL_STREAM_DATA_SOURCE_H */
