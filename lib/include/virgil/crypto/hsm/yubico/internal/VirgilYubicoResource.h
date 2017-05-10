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

#ifndef VIRGIL_CRYPTO_HSM_YUBICO_RESOURCE_HPP
#define VIRGIL_CRYPTO_HSM_YUBICO_RESOURCE_HPP

#include <virgil/crypto/hsm/yubico/VirgilHsmYubicoError.h>

#include <yubico/yubicrypt.h>

#include <functional>

namespace virgil { namespace crypto { namespace hsm { namespace yubico { namespace internal {

template<
        typename T,
        typename Creator,
        typename Destroyer
>
class yubico_resource {
public:
    yubico_resource(Creator creator, Destroyer destroyer)
            : resource_(nullptr), creator_(creator), destroyer_(destroyer) {
    }

    template<typename ...Args>
    yc_rc create(Args&& ... args) {
        return creator_(std::forward<Args>(args)..., &resource_);
    }

    template<
            typename Func,
            typename ...Args
    >
    yc_rc apply(Func func, Args&& ...args) {
        if (resource_ == nullptr) {
            throw make_error(VirgilHsmError::InvalidParams,
                    "Yubico resource was not created yet, but apply() function was invoked.");
        }
        return func(resource_, std::forward<Args>(args)...);
    }

    yc_rc destroy() noexcept {
        yc_rc rc = YCR_SUCCESS;
        if (resource_ != nullptr) {
            rc = destroyer_(resource_);
            resource_ = nullptr;
        }
        return rc;
    }

    ~yubico_resource() noexcept {
        destroy();
    }

    operator bool() const noexcept {
        return resource_ != nullptr;
    }

    bool isAlive() const noexcept {
        return resource_ != nullptr;
    }

    T* get() noexcept {
        return resource_;
    }

    yubico_resource(yubico_resource&&) = default;

    yubico_resource& operator=(yubico_resource&&) = default;

private:
    T* resource_ = { nullptr };
    Creator creator_;
    Destroyer destroyer_;
};

template<
        typename T,
        typename Creator,
        typename Destroyer
>
inline yubico_resource<T, Creator, Destroyer> make_yubico_resource(Creator creator, Destroyer destroyer) {
    return yubico_resource<T, Creator, Destroyer>(creator, destroyer);
};

using yubico_connector = decltype(make_yubico_resource<yc_connector>(yc_connect_best, yc_disconnect));

inline yubico_connector make_yubico_connector() {
    return make_yubico_resource<yc_connector>(yc_connect_best, yc_disconnect);
}

using yubico_session = decltype(make_yubico_resource<yc_session>(yc_create_session_derived, yc_destroy_session));

inline yc_rc dispose_yubico_session(yc_session* session) {
    (void) yc_util_close_session(session);
    (void) yc_destroy_session(session);
    return YCR_SUCCESS;
}

inline yubico_session make_yubico_session() {
    return make_yubico_resource<yc_session>(yc_create_session_derived, dispose_yubico_session);
}

}}}}}

#endif //VIRGIL_CRYPTO_HSM_YUBICO_RESOURCE_HPP
