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

# benchmark source code repository
git_repository(
    name = "com_google_benchmark",
    remote = "https://github.com/google/benchmark",
    commit = "0d98dba29d66e93259db7daa53a9327df767a415",
    shallow_since = "1641842067 +0000",
)

# boost libraries
git_repository(
    name = "com_github_nelhage_rules_boost",
    remote = "https://github.com/nelhage/rules_boost",
    commit = "685557254da7ee57afc1204189b58253972e16be",
    shallow_since = "1642479500 -0800",
)
load("@com_github_nelhage_rules_boost//:boost/boost.bzl", "boost_deps")
boost_deps()

# boringssl source code repository
git_repository(
    name = "boringssl",
    remote = "https://github.com/google/boringssl.git",
    commit = "2a0e6de411bb141e2fe169cee445741137478ef3",
    shallow_since = "1641854268 +0000",
)

# brotli source code repository
git_repository(
    name = "brotli",
    remote = "https://github.com/google/brotli",
    commit = "e61745a6b7add50d380cfd7d3883dd6c62fc2c71",
    shallow_since = "1598537575 +0200",
)

# googletest source code repository
git_repository(
    name = "com_google_googletest",
    remote = "https://github.com/google/googletest",
    commit = "e2239ee6043f73722e7aa812a459f54a28552929",
    shallow_since = "1623433346 -0700",
)

# jsoncpp source code repository
git_repository(
    name = "jsoncpp",
    remote = "https://github.com/open-source-parsers/jsoncpp",
    commit = "5defb4ed1a4293b8e2bf641e16b156fb9de498cc",
    shallow_since = "1635962008 -0500",
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

# cpp-httplib source code repository
http_archive(
    name = "cpp_http",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "cpp-httplib-0.10.1",
    url = "https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.10.1.zip",
    sha256 = "4576b7f1775cc25ab5f76a9be8798910f756792e45b372127b0f5c018e86145e",
)

# drogo source code repository
http_archive(
    name = "drogon",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "drogon-1.7.5-with-trantor-v1.5.5",
    url = "https://github.com/maaku/drogon/archive/refs/tags/v1.7.5-with-trantor-v1.5.5.tar.gz",
    sha256 = "f0b5ad1bb3dacba53dc747756d98d6fe657c1a158d2a80e339c975558bf6679f",
)

# hiredis source code repository
http_archive(
    name = "hiredis",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "hiredis-1.0.2",
    url = "https://github.com/redis/hiredis/archive/refs/tags/v1.0.2.tar.gz",
    sha256 = "e0ab696e2f07deb4252dda45b703d09854e53b9703c7d52182ce5a22616c3819",
    patch_args = ["-p1"],
    patches = [
        "patches/hiredis/static-libs.patch",
    ],
)

# univalue source code repository
http_archive(
    name = "univalue",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "univalue-1.1.1",
    url = "https://github.com/jgarzik/univalue/archive/refs/tags/v1.1.1.zip",
    sha256 = "50a4e306c782c77b84dee5c53049c0a072e1973d6bb76141cf41cec6ae57649f",
)

# uuid source code repository
http_archive(
    name = "uuid",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "uuid-1.6.2",
    url = "https://src.fedoraproject.org/repo/pkgs/uuid/uuid-1.6.2.tar.gz/5db0d43a9022a6ebbbc25337ae28942f/uuid-1.6.2.tar.gz",
    sha256 = "11a615225baa5f8bb686824423f50e4427acd3f70d394765bdff32801f0fd5b0",
)

# zlib source code repository
http_archive(
    name = "zlib",
    build_file_content = _ALL_CONTENT,
    strip_prefix = "zlib-1.2.12",
    url = "https://zlib.net/zlib-1.2.12.tar.gz",
    sha256 = "91844808532e5ce316b3c010929493c0244f3d37593afd6de04f71821d5136d9",
)

# End of File
