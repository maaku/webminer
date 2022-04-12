// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef WALLET_H

#include <stdint.h>

#include <mutex>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "crypto/sha256.h"
#include "sqlite3.h"
#include "support/allocators/secure.h"
#include "uint256.h"

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"

#include "absl/time/time.h"

#include "boost/filesystem.hpp"
#include "boost/interprocess/sync/file_lock.hpp"

struct Amount {
    int64_t i64;

    Amount() : i64(0) {}
    Amount(int64_t _i64) : i64(_i64) {}

    bool parse(const absl::string_view& str);

    inline Amount& operator+=(const Amount& rhs) { i64 += rhs.i64; return *this; }
    inline Amount& operator-=(const Amount& rhs) { i64 -= rhs.i64; return *this; }
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

    SecretWebcash() {}
    SecretWebcash(Amount _amount, const std::string& _sk) : sk(_sk), amount(_amount) {}
};

SecureString to_string(const SecretWebcash& esk);

struct PublicWebcash {
    uint256 pk;
    Amount amount;

    PublicWebcash() {}
    PublicWebcash(Amount _amount, const uint256& _pk) : pk(_pk), amount(_amount) {}
    PublicWebcash(const SecretWebcash& esk)
        : amount(esk.amount)
    {
        CSHA256()
            .Write((const unsigned char*)esk.sk.c_str(), esk.sk.size())
            .Finalize(pk.data());
    }
};

std::string to_string(const PublicWebcash& epk);

struct SqlNull {
};

struct SqlBool {
    bool b;

    SqlBool() : b(false) {}
    SqlBool(bool _b) : b(_b) {}
};

struct SqlInteger {
    int64_t i;

    SqlInteger() : i(0) {}
    SqlInteger(int64_t _i) : i(_i) {}
};

struct SqlFloat {
    double d;

    SqlFloat() : d(0.0) {}
    SqlFloat(double _d) : d(_d) {}
};

struct SqlText {
    std::string s;

    template<typename... Args>
    SqlText(Args&&... args) : s(std::forward<Args>(args)...) {}
};

struct SqlBlob {
    std::vector<unsigned char> vch;

    template<typename... Args>
    SqlBlob(Args&&... args) : vch(std::forward<Args>(args)...) {}
};

typedef std::variant<SqlNull, SqlBool, SqlInteger, SqlFloat, SqlText, SqlBlob> SqlValue;
typedef std::map<std::string, SqlValue> SqlParams;

struct WalletSecret {
    int id;
    absl::Time timestamp;
    std::string secret;
    bool mine;
    bool sweep;
};

struct WalletOutput {
    int id;
    absl::Time timestamp;
    uint256 hash;
    std::unique_ptr<WalletSecret> secret;
    Amount amount;
    bool spent;
};

class Wallet {
protected:
    std::mutex m_mut;

    boost::filesystem::path m_logfile;
    boost::interprocess::file_lock m_db_lock;
    sqlite3* m_db;

    bool ExecuteSql(const std::string& sql, const SqlParams& params);

    int m_hdroot_id;
    uint256 m_hdroot;

    void UpgradeDatabase();
    void GetOrCreateHDRoot();

    WalletSecret ReserveSecret(absl::Time timestamp, bool mine, bool sweep);
    int AddSecretToWallet(absl::Time timestamp, const SecretWebcash& sk, bool mine, bool sweep);
    int AddOutputToWallet(absl::Time timestamp, const PublicWebcash& pk, int secret_id, bool spent);

    std::vector<std::pair<WalletSecret, int>> ReplaceWebcash(absl::Time timestamp, std::vector<WalletOutput>& inputs, const std::vector<std::pair<WalletSecret, Amount>>& outputs);

public:
    Wallet(const boost::filesystem::path& path);
    ~Wallet();

    bool Insert(const SecretWebcash& sk, bool mine);

    // Have *any* terms of service been accepted?
    bool HaveAcceptedTerms() const;
    // Have the specific terms of service been accepted?
    bool AreTermsAccepted(const std::string& terms) const;
    // Mark the specified terms of service as accepted.
    void AcceptTerms(const std::string& terms);
};

#endif // WALLET_H

// End of File
