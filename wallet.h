// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef WALLET_H
#define WALLET_H

#include "webcash.h"

#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "absl/time/time.h"

#include "boost/filesystem.hpp"
#include "boost/interprocess/sync/file_lock.hpp"

#include "sqlite3.h"

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
