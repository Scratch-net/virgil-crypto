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

#include <virgil/crypto/hsm/VirgilHsmError.h>

using virgil::crypto::hsm::VirgilHsmErrorCategory;

const char* VirgilHsmErrorCategory::name() const noexcept {
    return "virgil/crypto/hsm";
}


std::string VirgilHsmErrorCategory::message(int ev) const noexcept {
    switch (static_cast<VirgilHsmError>(ev)) {
        case VirgilHsmError::MemoryError:
            return "Memory error.";
        case VirgilHsmError::InitError:
            return "Init error.";
        case VirgilHsmError::NetError:
            return "Net error.";
        case VirgilHsmError::ConnectorNotFound:
            return "Connector not found.";
        case VirgilHsmError::InvalidParams:
            return "Invalid parameters.";
        case VirgilHsmError::WrongLength:
            return "Wrong length.";
        case VirgilHsmError::BufferTooSmall:
            return "Buffer too small.";
        case VirgilHsmError::CryptogramMismatch:
            return "Cryptogram error.";
        case VirgilHsmError::AuthSessionError:
            return "Authenticate session error.";
        case VirgilHsmError::MacMismatch:
            return "MAC not matching.";
        case VirgilHsmError::DeviceOk:
            return "Device success.";
        case VirgilHsmError::DeviceInvCommand:
            return "Invalid command.";
        case VirgilHsmError::DeviceInvData:
            return "Malformed command / invalid data.";
        case VirgilHsmError::DeviceInvSession:
            return "Invalid session.";
        case VirgilHsmError::DeviceAuthFail:
            return "Message encryption / verification failed.";
        case VirgilHsmError::DeviceSessionsFull:
            return "All sessions are allocated.";
        case VirgilHsmError::DeviceSessionFailed:
            return "Session creation failed.";
        case VirgilHsmError::DeviceStorageFailed:
            return "Storage failure.";
        case VirgilHsmError::DeviceWrongLength:
            return "Wrong length.";
        case VirgilHsmError::DeviceInvPermission:
            return "Wrong permissions for operation.";
        case VirgilHsmError::DeviceLogFull:
            return "Log buffer is full and forced audit is set.";
        case VirgilHsmError::DeviceObjNotFound:
            return "Object not found.";
        case VirgilHsmError::DeviceIdIllegal:
            return "Id use is illegal.";
        case VirgilHsmError::DeviceInvalidOtp:
            return "OTP submitted is invalid.";
        case VirgilHsmError::DeviceDemoMode:
            return "Device is in demo mode and has to be power cycled.";
        case VirgilHsmError::InvalidOperation:
            return "Invalid operation.";
        case VirgilHsmError::UnsupportedAlgorithm:
            return "Unsupported algorithm.";
        default:
            return "Unknown error.";
    }
}

const VirgilHsmErrorCategory& virgil::crypto::hsm::hsm_category() noexcept {
    static VirgilHsmErrorCategory inst;
    return inst;
}
