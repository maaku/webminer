// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef WALLET_H

#include <stdint.h>

#include <mutex>
#include <string>

#include "crypto/sha256.h"
#include "sqlite3.h"
#include "uint256.h"

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"

#include "boost/filesystem.hpp"
#include "boost/interprocess/sync/file_lock.hpp"

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
    uint256 sk;
    Amount amount;
};

std::string to_string(const SecretWebcash& esk);

struct PublicWebcash {
    uint256 pk;
    Amount amount;

    PublicWebcash(const SecretWebcash& esk)
        : amount(esk.amount)
    {
        std::string hex = absl::BytesToHexString(absl::string_view((const char*)esk.sk.data(), esk.sk.size()));
        CSHA256()
            .Write((const unsigned char*)hex.c_str(), hex.size())
            .Finalize(pk.data());
    }
};

std::string to_string(const PublicWebcash& epk);

class Wallet {
protected:
    std::mutex m_mut;

    boost::filesystem::path m_logfile;
    boost::interprocess::file_lock m_db_lock;
    sqlite3* m_db;

    void UpgradeDatabase();

public:
    Wallet(const boost::filesystem::path& path);
    ~Wallet();

    bool Insert(const SecretWebcash& sk);

    // Have *any* terms of service been accepted?
    bool HaveAcceptedTerms() const;
    // Have the specific terms of service been accepted?
    bool AreTermsAccepted(const std::string& terms) const;
    // Mark the specified terms of service as accepted.
    void AcceptTerms(const std::string& terms);
};

#endif // WALLET_H

// End of File
