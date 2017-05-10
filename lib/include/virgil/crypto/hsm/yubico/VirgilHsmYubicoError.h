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

#ifndef VIRGIL_CRYPTO_HSM_YUBICO_ERROR_H
#define VIRGIL_CRYPTO_HSM_YUBICO_ERROR_H

#include <virgil/crypto/hsm/VirgilHsmError.h>


namespace virgil { namespace crypto { namespace hsm { namespace yubico {

bool hsm_yubico_is_success(int result);

std::string hsm_yubico_str_error(int error);

VirgilHsmError hsm_yubico_map_error(int error);

/**
 * @brief Handle value returned by Yubico library.
 *
 * If given value is an error then VirgilCryptoException will be thrown with appropriate description.
 * If given value is not an error then it will be returned.
 *
 * @param result Value returned by HSM Yubico library.
 * @return Value if it's not an error.
 * @throw VirgilCryptoException with given error code and correspond category, if given value represents an error.
 * @ingroup error
 */
inline int hsm_yubico_handler_get_result(int result) {
    if (hsm_yubico_is_success(result)) { return result; }
    throw make_error(hsm_yubico_map_error(result), hsm_yubico_str_error(result));
}

/**
 * @brief Handle value returned by Yubico library.
 *
 * This function is useful if thrown exception SHOULD be wrapped.
 * Initial exception can be accessed via std::current_exception(), or std::throw_with_nested().
 *
 * If given value is an error then VirgilCryptoException will be thrown with appropriate description.
 * If given value is not an error then it will be returned.
 *
 * @param result Value returned by HSM Yubico library.
 * @param catch_handler Function that can handle the error in a different way.
 *
 * @return Value if it's not an error.
 * @ingroup error
 */
template<typename CatchHandler>
inline int hsm_yubico_handler_get_result(int result, CatchHandler catch_handler) {
    if (hsm_yubico_is_success(result)) { return result; }
    try {
        throw make_error(hsm_yubico_map_error(result), hsm_yubico_str_error(result));
    } catch (...) {
        catch_handler(result);
        return 0;
    }
}

/**
 * @brief Handle value returned by Yubico library.
 *
 * If given value is an error then VirgilCryptoException will be thrown with appropriate description.
 * If given value is not an error then do nothing.
 *
 * @param result Value returned by HSM Yubico library.
 * @throw VirgilCryptoException with given error code and correspond category, if given value represents an error.
 * @ingroup error
 */
inline void hsm_yubico_handler(int result) {
    (void) hsm_yubico_handler_get_result(result);
}

/**
 * @brief Handle value returned by Yubico library.
 *
 * This function is useful if thrown exception SHOULD be wrapped or error can be handled in a different way.
 * Initial exception can be accessed via std::current_exception(), or std::throw_with_nested().
 *
 * If given value is an error then VirgilCryptoException will be thrown with appropriate description.
 * If given value is not an error then do nothing.
 *
 * @param result Value returned by HSM Yubico library.
 * @param catch_handler Function that can handle the error in a different way.
 * @ingroup error
 */
template<typename CatchHandler>
inline void hsm_yubico_handler(int result, CatchHandler catch_handler) {
    (void) hsm_yubico_handler_get_result<CatchHandler>(result, catch_handler);
}

}}}}

#endif //VIRGIL_CRYPTO_HSM_YUBICO_ERROR_H
