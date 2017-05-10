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

#ifndef VIRGIL_CRYPTO_HSM_ERROR_H
#define VIRGIL_CRYPTO_HSM_ERROR_H

#include <limits>
#include <system_error>

#include <virgil/crypto/VirgilCryptoException.h>

namespace virgil { namespace crypto { namespace hsm {

/**
 * @brief Specific error codes for the HSM.
 * @ingroup error
*/
enum class VirgilHsmError {
    MemoryError, ///< Memory error
    InitError, ///< Init error
    NetError, ///< Net error
    ConnectorNotFound, ///< Connector not found
    InvalidParams, ///< Invalid parameters
    WrongLength, ///< Wrong length
    BufferTooSmall, ///< Buffer too small
    CryptogramMismatch, ///< Cryptogram error
    AuthSessionError, ///< Authenticate session error
    MacMismatch, ///< MAC not matching
    DeviceOk, ///< Device success
    DeviceInvCommand, ///< Invalid command
    DeviceInvData, ///< Malformed command / invalid data
    DeviceInvSession, ///< Invalid session
    DeviceAuthFail, ///< Message encryption / verification failed
    DeviceSessionsFull, ///< All sessions are allocated
    DeviceSessionFailed, ///< Session creation failed
    DeviceStorageFailed, ///< Storage failure
    DeviceWrongLength, ///< Wrong length
    DeviceInvPermission, ///< Wrong permissions for operation
    DeviceLogFull, ///< Log buffer is full and forced audit is set
    DeviceObjNotFound, ///< Object not found
    DeviceIdIllegal, ///< Id use is illegal
    DeviceInvalidOtp, ///< OTP submitted is invalid
    DeviceDemoMode, ///< Device is in demo mode and has to be power cycled
    GenericError, ///< Unknown error
    InvalidOperation, ///< Operation can be processed
    UnsupportedAlgorithm, ///< Operation can be processed
    UnknownError = std::numeric_limits<int>::max()
};

/**
 * @brief This is specific error category that contains information about HSM errors.
 * @ingroup error
 */
class VirgilHsmErrorCategory : public std::error_category {
public:
    /**
     * @return Category name.
     */
    const char* name() const noexcept override;

    /**
     *
     * @param ev Error value.
     * @return Error description for given error value.
     * @see VirgilHsmError for specific error values.
     */
    std::string message(int ev) const noexcept override;
};

/**
 * @brief Return singleton instance of the HSM category.
 * @return Instance of the HSM category.
 * @ingroup error
 */
const VirgilHsmErrorCategory& hsm_category() noexcept;

/**
 * @brief Build exception with given error value and correspond error category.
 * @param ev Error value.
 * @return Exception with given error value and correspond error category.
 * @see VirgilHsmError for specific error values.
 * @ingroup error
 */
inline VirgilCryptoException make_error(VirgilHsmError ev) {
    return VirgilCryptoException(static_cast<int>(ev), hsm_category());
}

/**
 * @brief Build exception with given error value and correspond error category.
 * @param ev Error value.
 * @param what Additional error description.
 * @return Exception with given error value and correspond error category.
 * @see VirgilHsmError for specific error values.
 * @ingroup error
 */
inline VirgilCryptoException make_error(VirgilHsmError ev, const std::string& what) {
    return VirgilCryptoException(static_cast<int>(ev), hsm_category(), what);
}

/**
 * @brief Build exception with given error value and correspond error category.
 * @param ev Error value.
 * @param what Additional error description.
 * @return Exception with given error value and correspond error category.
 * @see VirgilHsmError for specific error values.
 * @ingroup error
 */
inline VirgilCryptoException make_error(VirgilHsmError ev, const char* what) {
    return VirgilCryptoException(static_cast<int>(ev), hsm_category(), what);
}

}}}


#endif //VIRGIL_CRYPTO_HSM_ERROR_H
