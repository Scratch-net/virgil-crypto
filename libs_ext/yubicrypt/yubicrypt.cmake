#
# Copyright (C) 2015-2016 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

#
# JUST INCLUDE this file. DO NOT use functions: virgil_depends() and virgil_find_package().
#

# Define yubicrypt root directory
string (TOLOWER ${CMAKE_SYSTEM_NAME} SYSTEM_NAME)
set (SYSTEM_ARCH_SUFFIX "-x86")
if (CMAKE_SIZEOF_VOID_P EQUAL 8)
    set (SYSTEM_ARCH_SUFFIX "-amd64")
endif ()

set (TARGET_OS_RELATIVE_PATH "${SYSTEM_NAME}${SYSTEM_ARCH_SUFFIX}")

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    execute_process (
        COMMAND cat /etc/os-release
        RESULT_VARIABLE GET_OS_INFO_RESULT
        OUTPUT_VARIABLE GET_OS_INFO_STDOUT
        ERROR_VARIABLE  GET_OS_INFO_STDERR
    )
    if (NOT GET_OS_INFO_RESULT STREQUAL "0")
        message ("ERROR: Can not inspect host system.")
        message (STATUS "ERROR: ${GET_OS_INFO_STDERR}")
        message (FATAL_ERROR)
    endif ()
    string (REGEX MATCH "ID=[^ \n\t]+" OS_INFO_ID_KEYPAIR ${GET_OS_INFO_STDOUT})
    string (REGEX MATCH "VERSION_ID=[^ \n\t]+" OS_INFO_VERSION_ID_KEYPAIR ${GET_OS_INFO_STDOUT})
    string (REGEX REPLACE "(ID=|\")" "" OS_INFO_ID ${OS_INFO_ID_KEYPAIR})
    string (REGEX REPLACE "(VERSION_ID=|\"|[.])" "" OS_INFO_VERSION_ID ${OS_INFO_VERSION_ID_KEYPAIR})
endif (CMAKE_SYSTEM_NAME MATCHES "Linux")

if (CMAKE_SYSTEM_NAME MATCHES "Darwin")
    set (OS_INFO_ID "macos")
    execute_process (
        COMMAND sw_vers
        RESULT_VARIABLE GET_OS_INFO_RESULT
        OUTPUT_VARIABLE GET_OS_INFO_STDOUT
        ERROR_VARIABLE  GET_OS_INFO_STDERR
    )
    if (NOT GET_OS_INFO_RESULT STREQUAL "0")
        message (STATUS "ERROR: Can not inspect host system.")
        message (STATUS "ERROR: ${GET_OS_INFO_STDERR}")
        message (FATAL_ERROR)
    endif ()
    string (REGEX MATCH "ProductVersion:[ \t]+[0-9]+[.][0-9]+" OS_INFO_VERSION_ID_KEYPAIR ${GET_OS_INFO_STDOUT})
    string (REGEX REPLACE "(ProductVersion:[ \t]+|[.])" "" OS_INFO_VERSION_ID ${OS_INFO_VERSION_ID_KEYPAIR})
endif (CMAKE_SYSTEM_NAME MATCHES "Darwin")


if (CMAKE_SYSTEM_NAME MATCHES "Windows")
    set (OS_INFO_ID "win")
    if (CMAKE_SIZEOF_VOID_P EQUAL 8)
        set (OS_INFO_VERSION_ID "64")
    endif ()
endif (CMAKE_SYSTEM_NAME MATCHES "Windows")

set (TARGET_OS_RELATIVE_PATH "${TARGET_OS_RELATIVE_PATH}/${OS_INFO_ID}${OS_INFO_VERSION_ID}")
set (TARGET_OS_PATH "${CMAKE_SOURCE_DIR}/libs_ext/yubicrypt/${TARGET_OS_RELATIVE_PATH}")
if (NOT EXISTS "${TARGET_OS_PATH}")
    message (STATUS "ERROR: Yubico does not have binaries for the ${CMAKE_SYSTEM_NAME} OS.")
    message (STATUS "ERROR: Expected binaries not found in location: ${TARGET_OS_PATH}.")
    message (FATAL_ERROR)
else ()
    message (STATUS "Yubico platform path: ${TARGET_OS_PATH}")
endif ()

# Set target includes and libaries within VIRGIL_DEPENDS_PREFIX
set (YUBICRYPT_INCLUDES "${VIRGIL_DEPENDS_PREFIX}/include")
set (YUBICRYPT_LIBRARIES_DIR "${VIRGIL_DEPENDS_PREFIX}/lib")

# Copy headers and libraries to the directory ${VIRGIL_DEPENDS_PREFIX}
file (INSTALL "${TARGET_OS_PATH}/include/" DESTINATION "${YUBICRYPT_INCLUDES}/yubico")
file (INSTALL "${TARGET_OS_PATH}/lib/" DESTINATION "${YUBICRYPT_LIBRARIES_DIR}")
if (EXISTS "${TARGET_OS_PATH}/bin/")
    set (YUBICRYPT_BIN_DIR "${VIRGIL_DEPENDS_PREFIX}/bin")
    file (INSTALL "${TARGET_OS_PATH}/bin/" DESTINATION "${YUBICRYPT_BIN_DIR}")
endif ()

find_library (YUBICRYPT_LIBRARY NAMES yubicrypt yubicrypt.dll HINTS "${YUBICRYPT_LIBRARIES_DIR}" NO_DEFAULT_PATH)
find_library (YUBICRYPT_LIBRARY_DEPS
    NAMES yubicrypt_pkcs11 libyubicrypt libeay32
    HINTS "${YUBICRYPT_LIBRARIES_DIR}" "${YUBICRYPT_BIN_DIR}"
    NO_DEFAULT_PATH
)

if (YUBICRYPT_LIBRARY)
    message (STATUS "INFO: Found Yubico libary: ${YUBICRYPT_LIBRARY}")
else (YUBICRYPT_LIBRARY)
    message (STATUS "ERROR: Yubico library is not found at path ${YUBICRYPT_LIBRARIES_DIR}.")
    message (FATAL_ERROR)
endif (YUBICRYPT_LIBRARY)

if (YUBICRYPT_LIBRARY_DEPS)
    message (STATUS "INFO: Found Yubico link dependencies: ${YUBICRYPT_LIBRARY_DEPS}")
else (YUBICRYPT_LIBRARY_DEPS)
    set (YUBICRYPT_LIBRARY_DEPS "")
endif (YUBICRYPT_LIBRARY_DEPS)

set (YUBICRYPT_LIBRARIES "${YUBICRYPT_LIBRARY}")

# Create target
set (YUBICRYPT_TARGET yubico::yubicrypt)

if (WIN32)
    add_library (${YUBICRYPT_TARGET} STATIC IMPORTED)
else (WIN32)
    add_library (${YUBICRYPT_TARGET} SHARED IMPORTED)
endif (WIN32)

set_target_properties(${YUBICRYPT_TARGET} PROPERTIES
    IMPORTED_LINK_INTERFACE_LANGUAGES "C"
    IMPORTED_LOCATION "${YUBICRYPT_LIBRARY}"
    INTERFACE_LINK_LIBRARIES "${YUBICRYPT_LIBRARY_DEPS}"
    INTERFACE_LINK_DEPS "${YUBICRYPT_LIBRARY_DEPS}"
    INTERFACE_INCLUDE_DIRECTORIES "${YUBICRYPT_INCLUDES}"
)
