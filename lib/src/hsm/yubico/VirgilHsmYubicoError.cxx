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

#include <virgil/crypto/hsm/yubico/VirgilHsmYubicoError.h>

#include <yubico/yubicrypt.h>

namespace virgil { namespace crypto { namespace hsm { namespace yubico {

bool hsm_yubico_is_success(int result) {
    return result == YCR_SUCCESS;
}

std::string hsm_yubico_str_error(int error) {
    if (error < YCR_GENERIC_ERROR) {
        return "Unknown error.";
    }
    return std::string(yc_strerror(static_cast<yc_rc>(error))) + ".";
}

VirgilHsmError hsm_yubico_map_error(int result) {
    if (result < YCR_GENERIC_ERROR) {
        return VirgilHsmError::UnknownError;
    }
    switch (static_cast<yc_rc>(result)) {
        case YCR_MEMORY:
            return VirgilHsmError::MemoryError;
        case YCR_INIT_ERROR:
            return VirgilHsmError::InitError;
        case YCR_NET_ERROR:
            return VirgilHsmError::NetError;
        case YCR_CONNECTOR_NOT_FOUND:
            return VirgilHsmError::ConnectorNotFound;
        case YCR_INVALID_PARAMS:
            return VirgilHsmError::InvalidParams;
        case YCR_WRONG_LENGTH:
            return VirgilHsmError::WrongLength;
        case YCR_BUFFER_TOO_SMALL:
            return VirgilHsmError::BufferTooSmall;
        case YCR_CRYPTOGRAM_MISMATCH:
            return VirgilHsmError::CryptogramMismatch;
        case YCR_AUTH_SESSION_ERROR:
            return VirgilHsmError::AuthSessionError;
        case YCR_MAC_MISMATCH:
            return VirgilHsmError::MacMismatch;
        case YCR_DEVICE_OK:
            return VirgilHsmError::DeviceOk;
        case YCR_DEVICE_INV_COMMAND:
            return VirgilHsmError::DeviceInvCommand;
        case YCR_DEVICE_INV_DATA:
            return VirgilHsmError::DeviceInvData;
        case YCR_DEVICE_INV_SESSION:
            return VirgilHsmError::DeviceInvSession;
        case YCR_DEVICE_AUTH_FAIL:
            return VirgilHsmError::DeviceAuthFail;
        case YCR_DEVICE_SESSIONS_FULL:
            return VirgilHsmError::DeviceSessionsFull;
        case YCR_DEVICE_SESSION_FAILED:
            return VirgilHsmError::DeviceSessionFailed;
        case YCR_DEVICE_STORAGE_FAILED:
            return VirgilHsmError::DeviceStorageFailed;
        case YCR_DEVICE_WRONG_LENGTH:
            return VirgilHsmError::DeviceWrongLength;
        case YCR_DEVICE_INV_PERMISSION:
            return VirgilHsmError::DeviceInvPermission;
        case YCR_DEVICE_LOG_FULL:
            return VirgilHsmError::DeviceLogFull;
        case YCR_DEVICE_OBJ_NOT_FOUND:
            return VirgilHsmError::DeviceObjNotFound;
        case YCR_DEVICE_ID_ILLEGAL:
            return VirgilHsmError::DeviceIdIllegal;
        case YCR_DEVICE_INVALID_OTP:
            return VirgilHsmError::DeviceInvalidOtp;
        case YCR_DEVICE_DEMO_MODE:
            return VirgilHsmError::DeviceDemoMode;
        case YCR_GENERIC_ERROR:
            return VirgilHsmError::GenericError;
        default:
            return VirgilHsmError::UnknownError;
    }
}

}}}}
