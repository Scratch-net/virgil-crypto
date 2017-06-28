# Generation 5 of the Virgil Crypto library.

## Introduction
Virgil Crypto library designed to cover diversity of use cases. It can be used in a small micro controller as well as in a high load server application.Therefore, features list and restrictions should be picked carefully.

## Features

### Common features

  * Provide API to the low-level crypto primitives, i.e. AES-256-GCM, SHA-256, ECC, etc.
  * Provide API to the high-level hybrid algorithms, i.e. ECIES, or Virgil Crypto.
  * Provide Crypto Agility that is agnostic to specific serialization format.
  * Keep algorithm parameters separately and implementation independently. This means that crypto primitives must operate only over raw data, i.e. raw public key, or raw private key.
  * Provide API that make possible to keep sensitive operations and related data, such as private key, or symmetric cipher, in a secure enclave, i.e. inside HSM or Intel SGX.
  * Replace algorithms implementation. If target platform has an optimized version of the specific algorithm it should be used instead of default one, i.e. use hardware optimization of SHA-256.
  * Add new algorithms to the known group, i.e. add ChaCha20 algorithm to the Symmetric Cipher group.
  * Add algorithm "best choice" if it’s available during runtime.
  * Support batch mode for verification, if possible.

### Compile time optimizations

  * Apply conditional compilation.
    - Enable or disable specific algorithm, i.e. use ECC and do not use RSA.
    - Restrict algorithm parameters, i.e. use AES with 256bit key and GCM mode only.

  * Reduce read-only memory size.
    - Optionally cut off string literals: debug messages, error messages, log messages.

  * Reduce stack size.
    - Configure size of statically allocated buffers.

  * Define custom memory allocators.
    - Optionally replace such functions as: malloc, calloc, free, realloc[deprecated].

## Requirements

### Software Requirements

  * Clear and clean interfaces.
  * Transparent error handling mechanism.
  * Transparent logging and debug mode.

## Restrictions

### Software restrictions

  * Use types from the "stdint.h".
  * Store static dictionaries in the ROM.
  * Reduce "mem copy" operations wherever possible.
  * Use "C" interface for non-OOD wrappers.
  * Use "C++" interface for OOD wrappers.
  * Do not use Cipher in the CBC mode.
