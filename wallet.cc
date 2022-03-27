// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "wallet.h"

#include "random.h"

#include <fstream>
#include <iostream>
#include <string>

#include <stdint.h>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

#include "absl/time/clock.h"
#include "absl/time/time.h"

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/interprocess/sync/file_lock.hpp"

#include "sqlite3.h"

// Requires an input that is a fractional-precision decimal with no more than 8
// digits past the decimal point, with a leading minus sign if the value is
// negative.  Extremely ficky parser that only values that could be output by
// to_string(const &Amount) defined below.
bool Amount::parse(const absl::string_view& str) {
    // Sanity: no empty strings allowed.
    if (str.empty()) {
        return false;
    }
    // Sanity: no embedded NUL characters allowed.
    if (str.size() != strnlen(str.data(), str.size())) {
        return false;
    }

    auto pos = str.begin();
    absl::int128 i = 0;

    bool negative = (*pos == '-');
    if (negative) {
        ++pos;
        // A single minus sign is not a valid encoding.
        if (pos == str.end()) {
            return false;
        }
    }

    // A leading zero is required, even for fractional amounts.
    if (!absl::ascii_isdigit(*pos)) {
        return false;
    }
    // But in that case the next character must be a decimal point.
    if (pos[0] == '0' && (pos + 1) != str.end() && pos[1] != '.') {
        return false;
    }

    for (; pos != str.end() && absl::ascii_isdigit(*pos); ++pos) {
        i *= 10;
        i += (*pos - '0');
        // Overflow check
        if (i > std::numeric_limits<int64_t>::max()) {
            return false;
        }
    }

    // Fractional digits are optional.
    int j = 0;
    if (pos != str.end()) {
        // Skip past the decimal point.
        if (*pos != '.') {
            return false;
        }
        ++pos;
        // If there is a decimal point, there must be at least one digit.
        if (pos == str.end()) {
            return false;
        }
        // Read up to 8 digits
        for (; j < 8 && pos != str.end(); ++j, ++pos) {
            if (!absl::ascii_isdigit(*pos)) {
                return false;
            }
            i *= 10;
            i += (*pos - '0');
        }
        // We must now be at the end of the input
        if (pos != str.end()) {
            return false;
        }
    }
    for (; j < 8; ++j) {
        i *= 10;
    }
    // Overflow check
    if (i > std::numeric_limits<int64_t>::max()) {
        return false;
    }

    i64 = static_cast<int64_t>(i);
    if (negative) {
        i64 = -i64;
    }
    return true;
}

// Returns the amount formatted as a fixed-precision decimal with 8 fractional
// digits, as per webcash tradition.  Any terminal zero fractional digits up to
// and including the decimal place itself are not output.
//     e.g. 3000000 is rendered as "0.03"
std::string to_string(const Amount& amt) {
    using std::to_string;
    std::lldiv_t div = std::lldiv(std::abs(amt.i64), 100000000LL);
    std::string res = (amt.i64 < 0) ? "-" : "";
    res += to_string(div.quot);
    if (div.rem) {
        std::string frac = to_string(div.rem);
        res.push_back('.');
        res.insert(res.end(), 8 - frac.length(), '0');
        res += frac;
        while (res.back() == '0') {
            res.pop_back();
        }
    }
    return res;
}

static std::string webcash_string(Amount amount, const absl::string_view& type, const uint256& hash)
{
    using std::to_string;
    if (amount.i64 < 0) {
        amount.i64 = 0;
    }
    return absl::StrCat("e", to_string(amount), ":", type, ":", absl::BytesToHexString(absl::string_view((const char*)hash.data(), hash.size())));
}

std::string to_string(const SecretWebcash& esk)
{
    return webcash_string(esk.amount, "secret", esk.sk);
}

std::string to_string(const PublicWebcash& epk)
{
    return webcash_string(epk.amount, "public", epk.pk);
}

void Wallet::UpgradeDatabase()
{
    std::array<std::string, 1> tables = {
        "CREATE TABLE IF NOT EXISTS 'terms' ("
            "'id' INTEGER PRIMARY KEY NOT NULL,"
            "'body' TEXT UNIQUE NOT NULL,"
            "'timestamp' INTEGER NOT NULL);",
    };

    for (const std::string& stmt : tables) {
        sqlite3_stmt* create_table;
        int res = sqlite3_prepare_v2(m_db, stmt.c_str(), stmt.size(), &create_table, nullptr);
        if (res != SQLITE_OK) {
            std::string msg(absl::StrCat("Unable to prepare SQL statement [\"", stmt, "\"]: ", sqlite3_errstr(res), " (", std::to_string(res), ")"));
            std::cerr << msg << std::endl;
            throw std::runtime_error(msg);
        }
        res = sqlite3_step(create_table);
        if (res != SQLITE_DONE) {
            std::string msg(absl::StrCat("Running SQL statement [\"", stmt, "\"] returned unexpected status code: ", sqlite3_errstr(res), " (", std::to_string(res), ")"));
            std::cerr << msg << std::endl;
            sqlite3_finalize(create_table);
            throw std::runtime_error(msg);
        }
        // Returns the same success/error code as the last invocation, so we can
        // ignore the return value here.
        sqlite3_finalize(create_table);
    }
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
    // Create the database file if it doesn't exist already, so that we can use
    // inter-process file locking primitives on it.  Note that an empty file is
    // a valid, albeit empty sqlite3 database.
    {
        boost::filesystem::ofstream db(dbfile.string(), boost::filesystem::ofstream::app);
        db.flush();
    }
    m_db_lock = boost::interprocess::file_lock(dbfile.c_str());
    if (!m_db_lock.try_lock()) {
        std::string msg("Unable to lock wallet database; wallet is in use by another process.");
        std::cerr << msg << std::endl;
        throw std::runtime_error(msg);
    }

    int error = sqlite3_open_v2(dbfile.c_str(), &m_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_EXRESCODE, nullptr);
    if (error != SQLITE_OK) {
        m_db_lock.unlock();
        std::string msg(absl::StrCat("Unable to open/create wallet database file: ", sqlite3_errstr(error), " (", std::to_string(error), ")"));
        std::cerr << msg << std::endl;
        throw std::runtime_error(msg);
    }
    UpgradeDatabase();

    // Touch the wallet file, which will create it if it doesn't already exist.
    // The file locking primitives assume that the file exists, so we need to
    // create here first.  It also allows the user to see the file even before
    // any wallet operations have been performed.
    {
        // This operation isn't protected by a filesystem lock, but that
        // shouldn't be an issue because it doesn't do anything else the file
        // didn't exist in the first place.
        boost::filesystem::ofstream bak(m_logfile.string(), boost::filesystem::ofstream::app);
        if (!bak) {
            sqlite3_close_v2(m_db); m_db = nullptr;
            m_db_lock.unlock();
            std::string msg(absl::StrCat("Unable to open/create wallet recovery file"));
            std::cerr << msg << std::endl;
            throw std::runtime_error(msg);
        }
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
    int error = sqlite3_close_v2(m_db); m_db = nullptr;
    if (error != SQLITE_OK) {
        std::cerr << "WARNING: sqlite3 returned error code " << sqlite3_errstr(error) << " (" << std::to_string(error) << ") when attempting to close database file of wallet.  Data loss may have occured." << std::endl;
    }
    // Release our filesystem lock on the wallet.
    m_db_lock.unlock();
}

bool Wallet::Insert(const SecretWebcash& sk)
{
    const std::lock_guard<std::mutex> lock(m_mut);
    return false;
}

bool Wallet::HaveAcceptedTerms() const
{
    static const std::string stmt = "SELECT EXISTS(SELECT 1 FROM 'terms')";
    sqlite3_stmt* have_any_terms;
    int res = sqlite3_prepare_v2(m_db, stmt.c_str(), stmt.size(), &have_any_terms, nullptr);
    if (res != SQLITE_OK) {
        std::string msg(absl::StrCat("Unable to prepare SQL statement [\"", stmt, "\"]: ", sqlite3_errstr(res), " (", std::to_string(res), ")"));
        std::cerr << msg << std::endl;
        throw std::runtime_error(msg);
    }
    res = sqlite3_step(have_any_terms);
    if (res != SQLITE_ROW) {
        std::string msg(absl::StrCat("Expected a result from executing SQL statement [\"", sqlite3_expanded_sql(have_any_terms), "\"] not: ", sqlite3_errstr(res), " (", std::to_string(res), ")"));
        std::cerr << msg << std::endl;
        sqlite3_finalize(have_any_terms);
        throw std::runtime_error(msg);
    }
    bool any = !!sqlite3_column_int(have_any_terms, 0);
    sqlite3_finalize(have_any_terms);
    return any;
}

bool Wallet::AreTermsAccepted(const std::string& terms) const
{
    static const std::string stmt = "SELECT EXISTS(SELECT 1 FROM 'terms' WHERE body=?)";
    sqlite3_stmt* have_terms;
    int res = sqlite3_prepare_v2(m_db, stmt.c_str(), stmt.size(), &have_terms, nullptr);
    if (res != SQLITE_OK) {
        std::string msg(absl::StrCat("Unable to prepare SQL statement [\"", stmt, "\"]: ", sqlite3_errstr(res), " (", std::to_string(res), ")"));
        std::cerr << msg << std::endl;
        throw std::runtime_error(msg);
    }
    res = sqlite3_bind_text(have_terms, 1, terms.c_str(), terms.size(), SQLITE_STATIC);
    if (res != SQLITE_OK) {
        std::string msg(absl::StrCat("Unable to bind parameter 1 in SQL statement [\"", stmt, "\"]: ", sqlite3_errstr(res), " (", std::to_string(res), ")"));
        std::cerr << msg << std::endl;
        sqlite3_finalize(have_terms);
        throw std::runtime_error(msg);
    }
    res = sqlite3_step(have_terms);
    if (res != SQLITE_ROW) {
        std::string msg(absl::StrCat("Expected a result from executing SQL statement [\"", sqlite3_expanded_sql(have_terms), "\"] not: ", sqlite3_errstr(res), " (", std::to_string(res), ")"));
        std::cerr << msg << std::endl;
        sqlite3_finalize(have_terms);
        throw std::runtime_error(msg);
    }
    bool have = !!sqlite3_column_int(have_terms, 0);
    sqlite3_finalize(have_terms);
    return have;
}

void Wallet::AcceptTerms(const std::string& terms)
{
    static const std::string stmt = "INSERT INTO 'terms' ('body', 'timestamp') VALUES (?, ?)";
    if (!AreTermsAccepted(terms)) {
        sqlite3_stmt* insert;
        int res = sqlite3_prepare_v2(m_db, stmt.c_str(), stmt.size(), &insert, nullptr);
        if (res != SQLITE_OK) {
            std::string msg(absl::StrCat("Unable to prepare SQL statement [\"", stmt, "\"]: ", sqlite3_errstr(res), " (", std::to_string(res), ")"));
            std::cerr << msg << std::endl;
            throw std::runtime_error(msg);
        }
        res = sqlite3_bind_text(insert, 1, terms.c_str(), terms.size(), SQLITE_STATIC);
        if (res != SQLITE_OK) {
            std::string msg(absl::StrCat("Unable to bind parameter 1 in SQL statement [\"", stmt, "\"]: ", sqlite3_errstr(res), " (", std::to_string(res), ")"));
            std::cerr << msg << std::endl;
            sqlite3_finalize(insert);
            throw std::runtime_error(msg);
        }
        int64_t timestamp = absl::ToUnixSeconds(absl::Now());
        res = sqlite3_bind_int64(insert, 2, timestamp);
        if (res != SQLITE_OK) {
            std::string msg(absl::StrCat("Unable to bind parameter 2 in SQL statement [\"", stmt, "\"]: ", sqlite3_errstr(res), " (", std::to_string(res), ")"));
            std::cerr << msg << std::endl;
            sqlite3_finalize(insert);
            throw std::runtime_error(msg);
        }
        res = sqlite3_step(insert);
        if (res != SQLITE_DONE) {
            std::string msg(absl::StrCat("Running SQL statment [\"", sqlite3_expanded_sql(insert), "\"] returned unexpected status code: ", sqlite3_errstr(res), " (", std::to_string(res), ")"));
            std::cerr << msg << std::endl;
            sqlite3_finalize(insert);
            throw std::runtime_error(msg);
        }
        sqlite3_finalize(insert);
    }
}

// End of File
