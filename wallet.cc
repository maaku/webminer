// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "wallet.h"

#include "random.h"

#include <iostream>
#include <string>

#include <stdint.h>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"

static std::string webcash_string(int64_t amount, const absl::string_view& type, const uint256& hash)
{
    if (amount < 0) {
        amount = 0;
    }
    return absl::StrCat("e", std::to_string(amount), ":", type, ":", absl::BytesToHexString(absl::string_view((const char*)hash.data(), hash.size())));
}

std::string to_string(const SecretWebcash& esk)
{
    return webcash_string(esk.amount, "secret", esk.sk);
}

std::string to_string(const PublicWebcash& epk)
{
    return webcash_string(epk.amount, "public", epk.pk);
}

Wallet::Wallet(const boost::filesystem::path& path)
    : m_logfile(path)
{
    // The caller can either give the path to one of the wallet files (the
    // recovery log or the sqlite3 database file), or to the shared basename of
    // these files.
    m_logfile.replace_extension(".bak");

    boost::filesystem::path dbfile(path);
    dbfile.replace_extension(".db");
    int error = sqlite3_open_v2(dbfile.c_str(), &m_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_EXRESCODE, nullptr);
    if (error != SQLITE_OK) {
        throw std::runtime_error(absl::StrCat("Unable to open/create wallet database file: ", sqlite3_errstr(error), " (", std::to_string(error), ")"));
    }

    // Touch the wallet file, which will create it if it doesn't already exist.
    // The file locking primitives assume that the file exists, so we need to
    // create here first.  It also allows the user to see the file even before
    // any wallet operations have been performed.
    {
        // This operation isn't protected by a filesystem lock, but that
        // shouldn't be an issue because it doesn't do anything else the file
        // didn't exist in the first place.
        boost::filesystem::ofstream bak(m_logfile, std::ofstream::app);
        bak.flush();
    }
}

Wallet::~Wallet()
{
    // Wait for other threads using the wallet to finish up.
    const std::lock_guard<std::mutex> lock(m_mut);
    // No errors are expected when closing the database file, but if there is
    // then that might be an indication of a serious bug or data loss the user
    // should know about.
    int error = sqlite3_close_v2(m_db);
    if (error != SQLITE_OK) {
        std::cerr << "WARNING: sqlite3 returned error code " << sqlite3_errstr(error) << " (" << std::to_string(error) << ") when attempting to close database file of wallet.  Data loss may have occured." << std::endl;
    }
}

bool Wallet::Insert(const SecretWebcash& sk)
{
    const std::lock_guard<std::mutex> lock(m_mut);
    return false;
}

// End of File
