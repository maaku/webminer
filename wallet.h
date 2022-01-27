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

#include "boost/filesystem.hpp"
#include "boost/interprocess/sync/file_lock.hpp"

struct SecretWebcash {
    uint256 sk;
    int64_t amount;
};

std::string to_string(const SecretWebcash& esk);

struct PublicWebcash {
    uint256 pk;
    int64_t amount;

    PublicWebcash(const SecretWebcash& esk)
        : amount(esk.amount)
    {
        CSHA256()
            .Write(esk.sk.data(), esk.sk.size())
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

public:
    Wallet(const boost::filesystem::path& path);
    ~Wallet();

    bool Insert(const SecretWebcash& sk);
};

#endif // WALLET_H

// End of File
