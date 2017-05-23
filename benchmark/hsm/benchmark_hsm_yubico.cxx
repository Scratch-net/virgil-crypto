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

/**
 * @file benchmark_signer.cxx
 * @brief Benchmark for encryption operations: sign and verify
 */

#define BENCHPRESS_CONFIG_MAIN

#include <benchpress.hpp>

#include <functional>

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilKeyPair.h>

#include <virgil/crypto/foundation/VirgilHash.h>
#include <virgil/crypto/hsm/yubico/VirgilHsmYubico.h>

using std::placeholders::_1;

using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilByteArrayUtils;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::foundation::VirgilHash;

using virgil::crypto::hsm::yubico::VirgilHsmYubico;

void benchmark_generate_key(benchpress::context* ctx, VirgilKeyPair::Algorithm keyAlgorithm) {
    auto hsm = VirgilHsmYubico();
    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        ctx->start_timer();
        auto key = hsm.generateKey(keyAlgorithm);
        ctx->stop_timer();
        hsm.deleteKey(key);
    }
}

void benchmark_sign(benchpress::context* ctx, VirgilKeyPair::Algorithm keyAlgorithm) {

    auto hsm = VirgilHsmYubico();

    const auto data = VirgilByteArrayUtils::stringToBytes("data to be signed");
    const auto digest = VirgilHash(VirgilHash::Algorithm::SHA384).hash(data);
    auto key = hsm.generateKey(keyAlgorithm);

    ctx->reset_timer();
    for (size_t i = 0; i < ctx->num_iterations(); ++i) {
        auto signature = hsm.signHash(digest, key);
    }
    ctx->stop_timer();

    hsm.deleteKey(key);
}

// RSA
BENCHMARK("Generate: RSA_2048", std::bind(benchmark_generate_key, _1, VirgilKeyPair::Algorithm::RSA_2048));
BENCHMARK("Generate: RSA_3072", std::bind(benchmark_generate_key, _1, VirgilKeyPair::Algorithm::RSA_3072));
BENCHMARK("Generate: RSA_4096", std::bind(benchmark_generate_key, _1, VirgilKeyPair::Algorithm::RSA_4096));

// NIST curve
BENCHMARK("Generate: EC_SECP256R1", std::bind(benchmark_generate_key, _1, VirgilKeyPair::Algorithm::EC_SECP256R1));
BENCHMARK("Generate: EC_SECP384R1", std::bind(benchmark_generate_key, _1, VirgilKeyPair::Algorithm::EC_SECP384R1));
BENCHMARK("Generate: EC_SECP521R1", std::bind(benchmark_generate_key, _1, VirgilKeyPair::Algorithm::EC_SECP521R1));

// Koblitz curve
BENCHMARK("Generate: EC_SECP256K1", std::bind(benchmark_generate_key, _1, VirgilKeyPair::Algorithm::EC_SECP256K1));

// Brainpool curve
BENCHMARK("Generate: EC_BP256R1", std::bind(benchmark_generate_key, _1, VirgilKeyPair::Algorithm::EC_BP256R1));
BENCHMARK("Generate: EC_BP384R1", std::bind(benchmark_generate_key, _1, VirgilKeyPair::Algorithm::EC_BP384R1));
BENCHMARK("Generate: EC_BP512R1", std::bind(benchmark_generate_key, _1, VirgilKeyPair::Algorithm::EC_BP512R1));

// RSA
BENCHMARK("Sign: RSA_2048", std::bind(benchmark_sign, _1, VirgilKeyPair::Algorithm::RSA_2048));
BENCHMARK("Sign: RSA_3072", std::bind(benchmark_sign, _1, VirgilKeyPair::Algorithm::RSA_3072));
BENCHMARK("Sign: RSA_4096", std::bind(benchmark_sign, _1, VirgilKeyPair::Algorithm::RSA_4096));

// NIST curve
BENCHMARK("Sign: EC_SECP256R1", std::bind(benchmark_sign, _1, VirgilKeyPair::Algorithm::EC_SECP256R1));
BENCHMARK("Sign: EC_SECP384R1", std::bind(benchmark_sign, _1, VirgilKeyPair::Algorithm::EC_SECP384R1));
BENCHMARK("Sign: EC_SECP521R1", std::bind(benchmark_sign, _1, VirgilKeyPair::Algorithm::EC_SECP521R1));

// Koblitz curve
BENCHMARK("Sign: EC_SECP256K1", std::bind(benchmark_sign, _1, VirgilKeyPair::Algorithm::EC_SECP256K1));

// Brainpool curve
BENCHMARK("Sign: EC_BP256R1", std::bind(benchmark_sign, _1, VirgilKeyPair::Algorithm::EC_BP256R1));
BENCHMARK("Sign: EC_BP384R1", std::bind(benchmark_sign, _1, VirgilKeyPair::Algorithm::EC_BP384R1));
BENCHMARK("Sign: EC_BP512R1", std::bind(benchmark_sign, _1, VirgilKeyPair::Algorithm::EC_BP512R1));
