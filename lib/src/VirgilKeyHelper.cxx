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

#include <virgil/crypto/foundation/VirgilKeyHelper.h>

#include <virgil/crypto/VirgilCryptoError.h>

#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>
#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>

#include <mbedtls/oid.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::VirgilCryptoError;
using virgil::crypto::make_error;
using virgil::crypto::foundation::VirgilKeyHelper;
using virgil::crypto::foundation::asn1::VirgilAsn1Reader;
using virgil::crypto::foundation::asn1::VirgilAsn1Writer;

#define OCTET_SIZE 8
#define SIZE_TO_OCTETS(size) ((size + 7) / OCTET_SIZE)
#define OID_STRING(x) std::string(x, MBEDTLS_OID_SIZE(x))
#define OID_EQUAL(oid_cstr, oid_str) \
        ( ( MBEDTLS_OID_SIZE(oid_cstr) == (oid_str).size() ) && \
          memcmp( (oid_cstr), (oid_str).c_str(), (oid_str).size()) == 0 )


bool VirgilKeyHelper::isEC(VirgilKeyPair::Algorithm keyAlgorithm) {
    switch (keyAlgorithm) {
        case VirgilKeyPair::Algorithm::EC_SECP192R1:
        case VirgilKeyPair::Algorithm::EC_SECP224R1:
        case VirgilKeyPair::Algorithm::EC_SECP256R1:
        case VirgilKeyPair::Algorithm::EC_SECP384R1:
        case VirgilKeyPair::Algorithm::EC_SECP521R1:
        case VirgilKeyPair::Algorithm::EC_BP256R1:
        case VirgilKeyPair::Algorithm::EC_BP384R1:
        case VirgilKeyPair::Algorithm::EC_BP512R1:
        case VirgilKeyPair::Algorithm::EC_SECP192K1:
        case VirgilKeyPair::Algorithm::EC_SECP224K1:
        case VirgilKeyPair::Algorithm::EC_SECP256K1:
        case VirgilKeyPair::Algorithm::EC_CURVE25519:
            return true;
        default:
            return false;
    }
}

bool VirgilKeyHelper::isRSA(VirgilKeyPair::Algorithm keyAlgorithm) {
    switch (keyAlgorithm) {
        case VirgilKeyPair::Algorithm::RSA_256:
        case VirgilKeyPair::Algorithm::RSA_512:
        case VirgilKeyPair::Algorithm::RSA_1024:
        case VirgilKeyPair::Algorithm::RSA_2048:
        case VirgilKeyPair::Algorithm::RSA_3072:
        case VirgilKeyPair::Algorithm::RSA_4096:
        case VirgilKeyPair::Algorithm::RSA_8192:
            return true;
        default:
            return false;
    }
}

VirgilByteArray VirgilKeyHelper::writePublicKeyEC(
        VirgilKeyPair::Algorithm keyAlgorithm, const VirgilByteArray& ecPointOctetString) {
    if (!isEC(keyAlgorithm)) {
        throw make_error(VirgilCryptoError::InvalidArgument, "Attempt to write EC Point for non EC key algorithm.");
    }

    VirgilAsn1Writer asn1Writer;

    size_t paramsLength{ 0 };
    paramsLength += asn1Writer.writeData(ecPointOctetString);
    paramsLength += asn1Writer.writeZero();
    paramsLength += asn1Writer.markBitString(paramsLength);

    size_t algorithmLength{ 0 };
    algorithmLength += asn1Writer.writeOID(getAlgorithmParamOID(keyAlgorithm));
    algorithmLength += asn1Writer.writeOID(getAlgorithmOID(keyAlgorithm));
    algorithmLength += asn1Writer.markSequence(algorithmLength);

    asn1Writer.writeSequence(algorithmLength + paramsLength);

    return asn1Writer.finish();
}

VirgilKeyHelper::RawKey VirgilKeyHelper::readPublicKeyEC(const VirgilByteArray& publicKey) {
    VirgilAsn1Reader asn1Reader(publicKey);
    asn1Reader.readSequence();
    asn1Reader.readSequence();
    auto algorithmOID = asn1Reader.readOID();
    auto paramOID = asn1Reader.readOID();
    auto ecPointOctetString = asn1Reader.readBitString();
    if (!ecPointOctetString.empty()) {
        return { getAlgorithmFromECParam(paramOID), ecPointOctetString };
    }
    throw make_error(VirgilCryptoError::InvalidFormat, "Empty public key was read.");
}

VirgilByteArray VirgilKeyHelper::writePublicKeyRSA(
        VirgilKeyPair::Algorithm keyAlgorithm, const VirgilByteArray& modulus, int publicExponent) {
    if (!isRSA(keyAlgorithm)) {
        throw make_error(VirgilCryptoError::InvalidArgument,
                "Attempt to write RSA parameters for non RSA key algorithm.");
    }

    VirgilAsn1Writer asn1Writer;

    size_t paramsLength{ 0 };
    paramsLength += asn1Writer.writeInteger(publicExponent);
    paramsLength += asn1Writer.writePositiveInteger(modulus);
    paramsLength += asn1Writer.markSequence(paramsLength);
    paramsLength += asn1Writer.writeZero();
    paramsLength += asn1Writer.markBitString(paramsLength);

    size_t algorithmLength{ 0 };
    algorithmLength += asn1Writer.writeNull();
    algorithmLength += asn1Writer.writeOID(getAlgorithmOID(keyAlgorithm));
    algorithmLength += asn1Writer.markSequence(algorithmLength);

    asn1Writer.markSequence(algorithmLength + paramsLength);

    return asn1Writer.finish();
}

std::string VirgilKeyHelper::getAlgorithmOID(VirgilKeyPair::Algorithm keyAlgorithm) {
    switch (keyAlgorithm) {
        case VirgilKeyPair::Algorithm::RSA_256:
        case VirgilKeyPair::Algorithm::RSA_512:
        case VirgilKeyPair::Algorithm::RSA_1024:
        case VirgilKeyPair::Algorithm::RSA_2048:
        case VirgilKeyPair::Algorithm::RSA_3072:
        case VirgilKeyPair::Algorithm::RSA_4096:
        case VirgilKeyPair::Algorithm::RSA_8192:
            return OID_STRING(MBEDTLS_OID_PKCS1_RSA);
        case VirgilKeyPair::Algorithm::EC_SECP192R1:
        case VirgilKeyPair::Algorithm::EC_SECP224R1:
        case VirgilKeyPair::Algorithm::EC_SECP256R1:
        case VirgilKeyPair::Algorithm::EC_SECP384R1:
        case VirgilKeyPair::Algorithm::EC_SECP521R1:
        case VirgilKeyPair::Algorithm::EC_BP256R1:
        case VirgilKeyPair::Algorithm::EC_BP384R1:
        case VirgilKeyPair::Algorithm::EC_BP512R1:
        case VirgilKeyPair::Algorithm::EC_SECP192K1:
        case VirgilKeyPair::Algorithm::EC_SECP224K1:
        case VirgilKeyPair::Algorithm::EC_SECP256K1:
        case VirgilKeyPair::Algorithm::EC_CURVE25519:
            return OID_STRING(MBEDTLS_OID_EC_ALG_UNRESTRICTED);
        case VirgilKeyPair::Algorithm::FAST_EC_ED25519:
            return OID_STRING(MBEDTLS_OID_ED25519);
        case VirgilKeyPair::Algorithm::FAST_EC_X25519:
            return OID_STRING(MBEDTLS_OID_X25519);
    }
}

std::string VirgilKeyHelper::getAlgorithmParamOID(VirgilKeyPair::Algorithm keyAlgorithm) {
    switch (keyAlgorithm) {
        case VirgilKeyPair::Algorithm::EC_SECP192R1:
            return OID_STRING(MBEDTLS_OID_EC_GRP_SECP192R1);
        case VirgilKeyPair::Algorithm::EC_SECP224R1:
            return OID_STRING(MBEDTLS_OID_EC_GRP_SECP224R1);
        case VirgilKeyPair::Algorithm::EC_SECP256R1:
            return OID_STRING(MBEDTLS_OID_EC_GRP_SECP256R1);
        case VirgilKeyPair::Algorithm::EC_SECP384R1:
            return OID_STRING(MBEDTLS_OID_EC_GRP_SECP384R1);
        case VirgilKeyPair::Algorithm::EC_SECP521R1:
            return OID_STRING(MBEDTLS_OID_EC_GRP_SECP521R1);
        case VirgilKeyPair::Algorithm::EC_BP256R1:
            return OID_STRING(MBEDTLS_OID_EC_GRP_BP256R1);
        case VirgilKeyPair::Algorithm::EC_BP384R1:
            return OID_STRING(MBEDTLS_OID_EC_GRP_BP384R1);
        case VirgilKeyPair::Algorithm::EC_BP512R1:
            return OID_STRING(MBEDTLS_OID_EC_GRP_BP512R1);
        case VirgilKeyPair::Algorithm::EC_SECP192K1:
            return OID_STRING(MBEDTLS_OID_EC_GRP_SECP192K1);
        case VirgilKeyPair::Algorithm::EC_SECP224K1:
            return OID_STRING(MBEDTLS_OID_EC_GRP_SECP224K1);
        case VirgilKeyPair::Algorithm::EC_SECP256K1:
            return OID_STRING(MBEDTLS_OID_EC_GRP_SECP256K1);
        case VirgilKeyPair::Algorithm::EC_CURVE25519:
            return OID_STRING(MBEDTLS_OID_EC_GRP_CURVE25519);
        default:
            return std::string();
    }
}

VirgilKeyPair::Algorithm VirgilKeyHelper::getAlgorithmFromRSASize(size_t rsaSizeBits) {
    switch (rsaSizeBits) {
        case 256:
            return VirgilKeyPair::Algorithm::RSA_256;
        case 512:
            return VirgilKeyPair::Algorithm::RSA_512;
        case 1024:
            return VirgilKeyPair::Algorithm::RSA_1024;
        case 2048:
            return VirgilKeyPair::Algorithm::RSA_2048;
        case 3072:
            return VirgilKeyPair::Algorithm::RSA_3072;
        case 4096:
            return VirgilKeyPair::Algorithm::RSA_4096;
        case 8192:
            return VirgilKeyPair::Algorithm::RSA_8192;
        default:
            throw make_error(VirgilCryptoError::UnsupportedAlgorithm, "Unsupported RSA key size.");
    }
}

VirgilKeyPair::Algorithm VirgilKeyHelper::getAlgorithmFromECParam(const std::string& oid) {
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_SECP192R1, oid)) {

    }
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_SECP192R1, oid)) {
        return VirgilKeyPair::Algorithm::EC_SECP192R1;
    }
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_SECP224R1, oid)) {
        return VirgilKeyPair::Algorithm::EC_SECP224R1;
    }
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_SECP256R1, oid)) {
        return VirgilKeyPair::Algorithm::EC_SECP256R1;
    }
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_SECP384R1, oid)) {
        return VirgilKeyPair::Algorithm::EC_SECP384R1;
    }
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_SECP521R1, oid)) {
        return VirgilKeyPair::Algorithm::EC_SECP521R1;
    }
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_BP256R1, oid)) {
        return VirgilKeyPair::Algorithm::EC_BP256R1;
    }
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_BP384R1, oid)) {
        return VirgilKeyPair::Algorithm::EC_BP384R1;
    }
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_BP512R1, oid)) {
        return VirgilKeyPair::Algorithm::EC_BP512R1;
    }
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_SECP192K1, oid)) {
        return VirgilKeyPair::Algorithm::EC_SECP192K1;
    }
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_SECP224K1, oid)) {
        return VirgilKeyPair::Algorithm::EC_SECP224K1;
    }
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_SECP256K1, oid)) {
        return VirgilKeyPair::Algorithm::EC_SECP256K1;
    }
    if (OID_EQUAL(MBEDTLS_OID_EC_GRP_CURVE25519, oid)) {
        return VirgilKeyPair::Algorithm::EC_CURVE25519;
    }
    throw make_error(VirgilCryptoError::UnsupportedAlgorithm, "Unsupported algorithm EC parameter.");
}

VirgilKeyPair::Algorithm VirgilKeyHelper::readAlgorithm(
        const VirgilByteArray& algorithmIdentifier, size_t encryptedDataSize) {
    VirgilAsn1Reader asn1Reader(algorithmIdentifier);

    asn1Reader.readSequence();
    auto algorithmOID = asn1Reader.readOID();

    if (OID_EQUAL(MBEDTLS_OID_PKCS1_RSA, algorithmOID)) {
        asn1Reader.readNull();
        const size_t encryptedDataSizeBits = encryptedDataSize << 3;
        return getAlgorithmFromRSASize(encryptedDataSizeBits);
    }

    if (OID_EQUAL(MBEDTLS_OID_EC_ALG_UNRESTRICTED, algorithmOID)) {
        auto ecGroupOID = asn1Reader.readOID();
        return getAlgorithmFromECParam(ecGroupOID);
    }

    if (OID_EQUAL(MBEDTLS_OID_ED25519, algorithmOID)) {
        asn1Reader.readNull();
        return VirgilKeyPair::Algorithm::FAST_EC_ED25519;
    }

    if (OID_EQUAL(MBEDTLS_OID_X25519, algorithmOID)) {
        asn1Reader.readNull();
        return VirgilKeyPair::Algorithm::FAST_EC_X25519;
    }

    throw make_error(VirgilCryptoError::UnsupportedAlgorithm);
}

VirgilByteArray VirgilKeyHelper::ecPointToOctetString(const VirgilByteArray& xy, bool doCompress) {
    if (VirgilByteArrayUtils::isZero(xy)) {
        return VirgilByteArray(1, 0x00);
    }

    const auto fieldSize = xy.size();
    const auto yStartPos = 0 + fieldSize /* skip X */;
    VirgilByteArray ecPointOctetString;
    if (doCompress) {
        const auto yStart = xy.cbegin() + yStartPos;
        const auto yEnd = xy.cend();
        const auto ySign = *yStart & 0x01;
        ecPointOctetString.reserve(1 * fieldSize + 1);
        ecPointOctetString.push_back(static_cast<VirgilByteArray::value_type>(0x02 + ySign));
        ecPointOctetString.insert(ecPointOctetString.end(), yStart, yEnd);
    } else {
        ecPointOctetString.reserve(2 * fieldSize + 1);
        ecPointOctetString.push_back(0x04);
        ecPointOctetString.insert(ecPointOctetString.end(), xy.cbegin(), xy.cend());
    }
    return ecPointOctetString;
}

VirgilByteArray VirgilKeyHelper::octetStringToECPoint(const VirgilByteArray& ecPointOctetString) {
    if (VirgilByteArrayUtils::isZero(ecPointOctetString)) {
        throw make_error(VirgilCryptoError::InvalidFormat, "Octet String with Elliptic Point is empty.");
    }

    if ((ecPointOctetString.front() & 0xF8) != 0) {
        throw make_error(VirgilCryptoError::InvalidFormat,
                "First byte of the Octet String with Elliptic Point is corrupted.");
    }

    bool isCompressed = ecPointOctetString.front() != 0x04;

    if (isCompressed) {
        throw make_error(VirgilCryptoError::UnsupportedAlgorithm, "Compressed Elliptic Curve Point is not supported.");
    }
    return VirgilByteArray(ecPointOctetString.cbegin() + 1, ecPointOctetString.cend());
}

VirgilByteArray VirgilKeyHelper::ecDeriveIntegerFromHash(const VirgilByteArray& digest, size_t keySize) {

    const auto leftmostNonZeroOctet = std::find_if_not(digest.cbegin(), digest.cend(),
            [](VirgilByteArray::const_reference value) {
                return value == 0x00;
            });

    const auto digestSize = std::distance(leftmostNonZeroOctet, digest.cend());

    VirgilByteArray result(keySize);
    if (digestSize <= result.size()) {
        const auto paddingSize = result.size() - digestSize;
        std::copy(leftmostNonZeroOctet, digest.end(), result.begin() + paddingSize);
    } else {
        std::copy(leftmostNonZeroOctet, leftmostNonZeroOctet + result.size(), result.begin());
    }

    return result;
}

size_t VirgilKeyHelper::getKeySize(VirgilKeyPair::Algorithm keyAlgorithm) {
    switch (keyAlgorithm) {
        case VirgilKeyPair::Algorithm::RSA_256:
            return SIZE_TO_OCTETS(256);
        case VirgilKeyPair::Algorithm::RSA_512:
            return SIZE_TO_OCTETS(512);
        case VirgilKeyPair::Algorithm::RSA_1024:
            return SIZE_TO_OCTETS(1024);
        case VirgilKeyPair::Algorithm::RSA_2048:
            return SIZE_TO_OCTETS(2048);
        case VirgilKeyPair::Algorithm::RSA_3072:
            return SIZE_TO_OCTETS(3072);
        case VirgilKeyPair::Algorithm::RSA_4096:
            return SIZE_TO_OCTETS(4096);
        case VirgilKeyPair::Algorithm::RSA_8192:
            return SIZE_TO_OCTETS(8192);
        case VirgilKeyPair::Algorithm::EC_SECP192R1:
            return SIZE_TO_OCTETS(192);
        case VirgilKeyPair::Algorithm::EC_SECP224R1:
            return SIZE_TO_OCTETS(224);
        case VirgilKeyPair::Algorithm::EC_SECP256R1:
            return SIZE_TO_OCTETS(256);
        case VirgilKeyPair::Algorithm::EC_SECP384R1:
            return SIZE_TO_OCTETS(384);
        case VirgilKeyPair::Algorithm::EC_SECP521R1:
            return SIZE_TO_OCTETS(521);
        case VirgilKeyPair::Algorithm::EC_BP256R1:
            return SIZE_TO_OCTETS(256);
        case VirgilKeyPair::Algorithm::EC_BP384R1:
            return SIZE_TO_OCTETS(384);
        case VirgilKeyPair::Algorithm::EC_BP512R1:
            return SIZE_TO_OCTETS(512);
        case VirgilKeyPair::Algorithm::EC_SECP192K1:
            return SIZE_TO_OCTETS(192);
        case VirgilKeyPair::Algorithm::EC_SECP224K1:
            return SIZE_TO_OCTETS(224);
        case VirgilKeyPair::Algorithm::EC_SECP256K1:
            return SIZE_TO_OCTETS(256);
        case VirgilKeyPair::Algorithm::EC_CURVE25519:
            return SIZE_TO_OCTETS(255);
        case VirgilKeyPair::Algorithm::FAST_EC_ED25519:
            return SIZE_TO_OCTETS(255);
        case VirgilKeyPair::Algorithm::FAST_EC_X25519:
            return SIZE_TO_OCTETS(255);
    }
}

#undef OCTET_SIZE
#undef SIZE_TO_OCTETS
#undef OID_STRING
#undef OID_EQUAL
