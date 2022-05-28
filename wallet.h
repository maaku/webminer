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

#include "boost/filesystem.hpp"
#include "boost/interprocess/sync/file_lock.hpp"

#include "sqlite3.h"

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
