# Copyright (c) 2022 Mark Friedenbach
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

# absl source code repository
git_repository(
    name = "com_google_absl",
    remote = "https://github.com/abseil/abseil-cpp.git",
    commit = "215105818dfde3174fe799600bb0f3cae233d0bf",
    shallow_since = "1635953174 -0400",
)

# boringssl source code repository
git_repository(
    name = "boringssl",
    remote = "https://github.com/google/boringssl.git",
    commit = "2a0e6de411bb141e2fe169cee445741137478ef3",
    shallow_since = "1641854268 +0000",
)

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "rules_foreign_cc",
    strip_prefix = "rules_foreign_cc-0.7.1",
    url = "https://github.com/bazelbuild/rules_foreign_cc/archive/refs/tags/0.7.1.zip",
    sha256 = "7350440503d8e3eafe293229ce5f135e8f65a59940e9a34614714f6063df72c3",
)

# This sets up some common toolchains for building targets; includes
# repositories needed by rules_foreign_cc, and creates some utilities
# for the host operating system.  For more details, please see:
# https://github.com/bazelbuild/rules_foreign_cc/tree/main/docs#rules_foreign_cc_dependencies
load("@rules_foreign_cc//foreign_cc:repositories.bzl", "rules_foreign_cc_dependencies")
rules_foreign_cc_dependencies()

# Group the sources of the library so that CMake rule have access to it
_ALL_CONTENT = """\
filegroup(
    name = "all_srcs",
    srcs = glob(["**"]),
    visibility = ["//visibility:public"],
)
"""

# libcpr source code repository
http_archive(
    name = "cpr",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "cpr-1.7.2",
    url = "https://github.com/libcpr/cpr/archive/refs/tags/1.7.2.zip",
    sha256 = "e1b208002cc1ccd1ab2e72943a377d760185bbe3276cb41d4144ce250de11b95",
)

# libcurl source code repository
http_archive(
    name = "curl",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "curl-curl-7_81_0",
    url = "https://github.com/curl/curl/archive/refs/tags/curl-7_81_0.zip",
    sha256 = "9edcf885a780f2c9b1a9f5c6b757c158cd11492811c68cd9e0655458c7945311",
)

# libgcrypt source code repository
http_archive(
    name = "gcrypt",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "libgcrypt-libgcrypt-1.8.8",
    url = "https://github.com/gpg/libgcrypt/archive/refs/tags/libgcrypt-1.8.8.zip",
    sha256 = "390272868bf0030d0c7b98a6e73092857bf105e3519bd77105b5d1b70f9ca226",
)

# libgpg-error source code repository
http_archive(
    name = "gpg_error",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "libgpg-error-libgpg-error-1.42",
    url = "https://github.com/gpg/libgpg-error/archive/refs/tags/libgpg-error-1.42.zip",
    sha256 = "0f4ff69c65578ae900f59cce9052e46dd795559620a7aba00637ba421620d223",
)

# OpenLDAP source code repository
http_archive(
    name = "ldap",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "openldap-OPENLDAP_REL_ENG_2_6_0",
    url = "https://github.com/openldap/openldap/archive/refs/tags/OPENLDAP_REL_ENG_2_6_0.zip",
    sha256 = "b55870513ea05e04a07accbb2029d68ee24097b879216680f1885426bca922b0",
)

# libssh2 source code repository
http_archive(
    name = "ssh2",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "libssh2-libssh2-1.10.0",
    url = "https://github.com/libssh2/libssh2/archive/refs/tags/libssh2-1.10.0.zip",
    sha256 = "b0d0d13ea9753ef737565864fad30600295baba53ecc77cfba3923ae0d7cbdf3",
)

# zlib-ng source code repository
http_archive(
    name = "zlib",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "zlib-ng-2.0.6",
    url = "https://github.com/zlib-ng/zlib-ng/archive/refs/tags/2.0.6.zip",
    sha256 = "cb8af7677e5f3bd9e56a6b1c384d9c17bf3d44aeb3c0523453f00772185b337a",
)

# End of File
