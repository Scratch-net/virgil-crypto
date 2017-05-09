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

#ifndef VIRGIL_CRYPTO_FOUNDATION_KEY_HELPER_H
#define VIRGIL_CRYPTO_FOUNDATION_KEY_HELPER_H

#include <virgil/crypto/VirgilKeyPair.h>

#include <string>

namespace virgil { namespace crypto { namespace foundation {

/**
 * @brief Provide information about Asymmetric algorithm and helps transform public keys.
 */
class VirgilKeyHelper {
public:
    /**
     * @brief Represents public key in the raw format (algorithm + Octet String).
     */
    struct RawKey {
        VirgilKeyPair::Algorithm algorithm; ///< Underlying key algorithm
        VirgilByteArray key; ///< Raw key as Octet String
    };
public:
    /**
     * @brief Avoid instances creation.
     */
    VirgilKeyHelper() = delete;

    /**
     * @brief Define if given algorithm belongs to the Elliptic Curve group.
     *
     * @param keyAlgorithm - algorithm under the check.
     * @return true if given algorithm belongs to the Elliptic Curve group, false - otherwise.
     */
    static bool isEC(VirgilKeyPair::Algorithm keyAlgorithm);

    /**
     * @brief Define if given algorithm belongs to the RSA group.
     *
     * @param keyAlgorithm - algorithm under the check.
     * @return true if given algorithm belongs to the RSA group, false - otherwise.
     */
    static bool isRSA(VirgilKeyPair::Algorithm keyAlgorithm);

    /**
     * @brief Write EC public key parameters to the SubjectPublicKeyInfo structure.
     *
     * @param keyAlgorithm - specific Elliptic Curve algorithm.
     * @param ecPointOctetString - Elliptic Curve Point represented as Octet String (see SEC1 2.3.3).
     * @return Public key in the SubjectPublicKeyInfo DER structure format.
     *
     * @code
     * Public key format:
     *     SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *         algorithm         AlgorithmIdentifier,
     *         subjectPublicKey  BIT STRING
     *     }
     *     ECPublicKey ::= EllipticCurvePoint
     *     EllipticCurvePoint ::= OCTET STRING  -- SEC1 2.3.3
     * @endcode
     */
    static VirgilByteArray writePublicKeyEC(
            VirgilKeyPair::Algorithm keyAlgorithm, const VirgilByteArray& ecPointOctetString);

    /**
     * @brief Read raw public key from the SubjectPublicKeyInfo DER structure.
     * @param publicKey - SubjectPublicKeyInfo DER structure.
     * @return Elliptic Curve Point as Octet String and correspond algorithm.
     * @note Elliptic Curve Point can be compressed or uncompressed, use uncompress function if needed.
     */
    static RawKey readPublicKeyEC(const VirgilByteArray& publicKey);

    /**
     * @brief Write RSA public key parameters to the SubjectPublicKeyInfo structure.
     *
     * @return Public key in the SubjectPublicKeyInfo DER structure format.
     *
     * @code
     * Public key format:
     *     SubjectPublicKeyInfo  ::=  SEQUENCE  {
     *          algorithm            AlgorithmIdentifier,
     *          subjectPublicKey     BIT STRING
     *     }
     *     RSAPublicKey ::= SEQUENCE {
     *         modulus           INTEGER,  -- n
     *         publicExponent    INTEGER   -- e
     *     }
     * @endcode
     */
    static VirgilByteArray writePublicKeyRSA(
            VirgilKeyPair::Algorithm keyAlgorithm, const VirgilByteArray& modulus, int publicExponent);

    /**
     * @brief Read key algorithm from the AlgorithmIdentifier structure.
     *
     * @param algorithmIdentifier - ASN.1 AlgorithmIdentifier structure.
     * @param encryptedDataSize - size of the encrypted data (used for RSA key size deduction).
     * @return Key algorithm.
     */
    static VirgilKeyPair::Algorithm readAlgorithm(const VirgilByteArray& algorithmIdentifier, size_t encryptedDataSize);

    /**
     * @brief Return key size in bytes.
     * @param keyAlgorithm - key algorithm.
     * @return Key size in bytes.
     */
    static size_t getKeySize(VirgilKeyPair::Algorithm keyAlgorithm);

    /**
     * @brief Convert Elliptic Curve Point to the Octet String.
     *
     * @param xy - xy = X || Y, where X and Y are field elements converted to the octets as specified in the SEC1 2.3.5.
     * @param doCompress - defines whether or not to represent points using point compression.
     * @return Elliptic Curve Point as Octet String.
     * @see SEC1 2.3.3
     */
    static VirgilByteArray ecPointToOctetString(const VirgilByteArray& xy, bool doCompress = false);

    /**
     * @brief Octet String to the Elliptic Curve Point.
     *
     * @param ecPointOctetString - Elliptic Curve Point as Octet String.
     * @return the Elliptic Curve Point as X || Y,
     *     where X and Y are field elements converted to the octets as specified in the SEC1 2.3.5
     * @see SEC1 2.3.4
     */
    static VirgilByteArray octetStringToECPoint(const VirgilByteArray& ecPointOctetString);

    /**
     * @brief Implement step 5 of the Elliptic Curve Signing Operation (SEC1 4.1.3)
     *
     * @param digest - source digest.
     * @param keySize - size in octets of the Elliptic Curve Key.
     * @return Derived digest to be signed in the next step.
     */
    static VirgilByteArray ecDeriveIntegerFromHash(const VirgilByteArray& digest, size_t keySize);

private:
    static std::string getAlgorithmOID(VirgilKeyPair::Algorithm keyAlgorithm);

    static std::string getAlgorithmParamOID(VirgilKeyPair::Algorithm keyAlgorithm);

    static VirgilKeyPair::Algorithm getAlgorithmFromRSASize(size_t rsaSizeBits);

    static VirgilKeyPair::Algorithm getAlgorithmFromECParam(const std::string& oid);
};

}}}

#endif //VIRGIL_CRYPTO_FOUNDATION_KEY_HELPER_H
