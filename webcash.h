// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef WEBCASH_H
#define WEBCASH_H

#include <string>

#include <stdint.h>

#include "crypto/sha256.h"
#include "support/allocators/secure.h"
#include "uint256.h"

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"

struct Amount {
    int64_t i64;

    Amount() : i64(0) {}
    Amount(int64_t _i64) : i64(_i64) {}

    bool parse(const absl::string_view& str);
};

inline bool operator==(const Amount& lhs, const Amount& rhs) { return lhs.i64 == rhs.i64; }
inline bool operator!=(const Amount& lhs, const Amount& rhs) { return lhs.i64 != rhs.i64; }

inline bool operator<(const Amount& lhs, const Amount& rhs) { return lhs.i64 < rhs.i64; }
inline bool operator<=(const Amount& lhs, const Amount& rhs) { return lhs.i64 <= rhs.i64; }
inline bool operator>=(const Amount& lhs, const Amount& rhs) { return lhs.i64 >= rhs.i64; }
inline bool operator>(const Amount& lhs, const Amount& rhs) { return lhs.i64 > rhs.i64; }

inline Amount operator-(const Amount& lhs, const Amount& rhs) { return Amount(lhs.i64 - rhs.i64); }
inline Amount operator+(const Amount& lhs, const Amount& rhs) { return Amount(lhs.i64 + rhs.i64); }

std::string to_string(const Amount& amt);

struct SecretWebcash {
    SecureString sk;
    Amount amount;

    bool parse(const absl::string_view& str);
};

inline bool operator==(const SecretWebcash& lhs, const SecretWebcash& rhs) { return std::tie(lhs.amount, lhs.sk) == std::tie(rhs.amount, rhs.sk); }
inline bool operator!=(const SecretWebcash& lhs, const SecretWebcash& rhs) { return std::tie(lhs.amount, lhs.sk) != std::tie(rhs.amount, rhs.sk); }

inline bool operator<(const SecretWebcash& lhs, const SecretWebcash& rhs) { return std::tie(lhs.amount, lhs.sk) < std::tie(rhs.amount, rhs.sk); }
inline bool operator<=(const SecretWebcash& lhs, const SecretWebcash& rhs) { return std::tie(lhs.amount, lhs.sk) <= std::tie(rhs.amount, rhs.sk); }
inline bool operator>=(const SecretWebcash& lhs, const SecretWebcash& rhs) { return std::tie(lhs.amount, lhs.sk) >= std::tie(rhs.amount, rhs.sk); }
inline bool operator>(const SecretWebcash& lhs, const SecretWebcash& rhs) { return std::tie(lhs.amount, lhs.sk) > std::tie(rhs.amount, rhs.sk); }

std::string to_string(const SecretWebcash& esk);

struct PublicWebcash {
    uint256 pk;
    Amount amount;

    PublicWebcash() = default;
    PublicWebcash(const SecretWebcash& esk)
        : amount(esk.amount)
    {
        CSHA256()
            .Write((const unsigned char*)esk.sk.c_str(), esk.sk.size())
            .Finalize(pk.data());
    }

    bool parse(const absl::string_view& str);
};

inline bool operator==(const PublicWebcash& lhs, const PublicWebcash& rhs) { return std::tie(lhs.amount, lhs.pk) == std::tie(rhs.amount, rhs.pk); }
inline bool operator!=(const PublicWebcash& lhs, const PublicWebcash& rhs) { return std::tie(lhs.amount, lhs.pk) != std::tie(rhs.amount, rhs.pk); }

inline bool operator<(const PublicWebcash& lhs, const PublicWebcash& rhs) { return std::tie(lhs.amount, lhs.pk) < std::tie(rhs.amount, rhs.pk); }
inline bool operator<=(const PublicWebcash& lhs, const PublicWebcash& rhs) { return std::tie(lhs.amount, lhs.pk) <= std::tie(rhs.amount, rhs.pk); }
inline bool operator>=(const PublicWebcash& lhs, const PublicWebcash& rhs) { return std::tie(lhs.amount, lhs.pk) >= std::tie(rhs.amount, rhs.pk); }
inline bool operator>(const PublicWebcash& lhs, const PublicWebcash& rhs) { return std::tie(lhs.amount, lhs.pk) > std::tie(rhs.amount, rhs.pk); }

std::string to_string(const PublicWebcash& epk);

#endif // WEBCASH_H

// End of File
