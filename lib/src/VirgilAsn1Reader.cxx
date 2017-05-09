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

#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>

#include <mbedtls/asn1.h>

#include <virgil/crypto/foundation/VirgilSystemCryptoError.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;

VirgilAsn1Reader::VirgilAsn1Reader() : p_(0), end_(0), data_() {
}

VirgilAsn1Reader::VirgilAsn1Reader(const VirgilByteArray& data) : p_(0), end_(0), data_() {
    this->reset(data);
}

VirgilAsn1Reader::~VirgilAsn1Reader() noexcept {
    p_ = 0;
    end_ = 0;
}

void VirgilAsn1Reader::reset(const VirgilByteArray& data) {
    data_ = data;
    p_ = data_.data();
    end_ = p_ + data_.size();
}

int VirgilAsn1Reader::readInteger() {
    checkState();
    int result;
    system_crypto_handler(
            mbedtls_asn1_get_int(&p_, end_, &result),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidFormat)); }
    );
    return result;
}

bool VirgilAsn1Reader::readBool() {
    checkState();
    int result;
    system_crypto_handler(
            mbedtls_asn1_get_bool(&p_, end_, &result),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidFormat)); }
    );
    return result == 0 ? false : true;
}

void VirgilAsn1Reader::readNull() {
    checkState();
    size_t len;
    system_crypto_handler(
            mbedtls_asn1_get_tag(&p_, end_, &len, MBEDTLS_ASN1_NULL),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidFormat)); }
    );
}

size_t VirgilAsn1Reader::readContextTag(unsigned char tag) {
    const unsigned char kAsn1Tag_Max = 0x1F;
    if (tag > kAsn1Tag_Max) {
        throw make_error(VirgilCryptoError::InvalidArgument, "Requested ASN.1 tag is greater then maximum allowed.");
    }
    if (p_ != 0 && end_ != 0 && p_ >= end_) {
        // Expected optional tag located at the end of the ASN.1 structure is absent.
        return 0;
    }
    checkState();
    size_t len;
    int result =
            mbedtls_asn1_get_tag(&p_, end_, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | tag);
    if (result == 0) {
        return len;
    } else if (result == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
        return 0;
    }
    throw make_error(VirgilCryptoError::InvalidFormat);
}

VirgilByteArray VirgilAsn1Reader::readOctetString() {
    checkState();
    size_t len;
    system_crypto_handler(
            mbedtls_asn1_get_tag(&p_, end_, &len, MBEDTLS_ASN1_OCTET_STRING),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidFormat)); }
    );
    p_ += len;
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(p_ - len, len);
}

VirgilByteArray VirgilAsn1Reader::readBitString() {
    checkState();
    mbedtls_asn1_bitstring bitString{ 0 };
    system_crypto_handler(
            mbedtls_asn1_get_bitstring(&p_, end_, &bitString),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidFormat)); }
    );
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(bitString.p, bitString.len);
}

VirgilByteArray VirgilAsn1Reader::readUTF8String() {
    checkState();
    size_t len;
    system_crypto_handler(
            mbedtls_asn1_get_tag(&p_, end_, &len, MBEDTLS_ASN1_UTF8_STRING),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidFormat)); }
    );
    p_ += len;
    return VIRGIL_BYTE_ARRAY_FROM_PTR_AND_LEN(p_ - len, len);
}

VirgilByteArray VirgilAsn1Reader::readData() {
    checkState();
    size_t len;
    unsigned char* dataStart = p_;
    p_ += 1; // Ignore tag value
    system_crypto_handler(
            mbedtls_asn1_get_len(&p_, end_, &len),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidFormat)); }
    );
    p_ += len;
    return VirgilByteArray(dataStart, p_);
}


std::string VirgilAsn1Reader::readOID() {
    checkState();
    size_t len;
    system_crypto_handler(
            mbedtls_asn1_get_tag(&p_, end_, &len, MBEDTLS_ASN1_OID),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidFormat)); }
    );
    p_ += len;
    return std::string(reinterpret_cast<std::string::const_pointer>(p_ - len), len);
}

size_t VirgilAsn1Reader::readSequence() {
    checkState();
    size_t len;
    system_crypto_handler(
            mbedtls_asn1_get_tag(&p_, end_, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidFormat)); }
    );
    return len;
}

size_t VirgilAsn1Reader::readSet() {
    checkState();
    size_t len;
    system_crypto_handler(
            mbedtls_asn1_get_tag(&p_, end_, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET),
            [](int) { std::throw_with_nested(make_error(VirgilCryptoError::InvalidFormat)); }
    );
    return len;
}

void VirgilAsn1Reader::checkState() {
    if (p_ == 0 || end_ == 0) {
        throw make_error(VirgilCryptoError::NotInitialized);
    }
    if (p_ >= end_) {
        throw make_error(VirgilCryptoError::InvalidState, "Attempt to read empty ASN.1 structure.");
    }
}


