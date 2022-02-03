// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "wallet.h"

#include "webcash.h"

#include <fstream>
#include <iostream>
#include <string>

#include <stdint.h>

#include "absl/strings/str_cat.h"

#include "absl/time/clock.h"
#include "absl/time/time.h"

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/interprocess/sync/file_lock.hpp"

#include "sqlite3.h"

// We group outputs based on their use.  There are currently four categories of
// webcash recognized by the wallet:
enum HashType : int {
    // Pre-generated key that hasn't yet been used for any purpose.  To make
    // backups possible and to minimize the chance of losing funds if/when
    // wallet corruption occurs, the wallet maintains a pool of pre-generated
    // secrets.  These are allocated and used, as needed, in FIFO order.
    UNUSED = -1,

    // Outputs generated as payments to others.  These are intended to be
    // immediately claimed by the other party, but we keep the key in this
    // wallet in case there are problems completing the transaction.
    PAYMENT = 0,

    // Outputs added via explicit import.  These are shown as visible, discrete
    // inputs to the wallet.  The wallet always redeems received webcash upon
    // import under the assumption that the imported secret value is still known
    // to others or otherwise not secure.
    RECEIVE = 1,

    // Internal webcash generated either to redeem payments or mined webcash,
    // change from a payment, or the consolidation of such outputs.  These
    // outputs count towards the current balance of the wallet, but aren't shown
    // explicitly.
    CHANGE = 2,

    // Outputs generated via a mining report.  These are seen as visible inputs
    // to a wallet, aggregated as "mining income."  The wallet always redeems
    // mining inputs for change immediately after generation, in case the mining
    // reports (which contain the secret) are made public.
    MINING = 3,
};

struct WalletSecret;

struct WalletOutput {
    int id;
    uint256 hash;
    std::unique_ptr<WalletSecret> secret;
    int64_t amount;
    bool spent;
};

struct WalletSecret {
    int id;
    uint256 secret;
    bool mine;
    bool sweep;
};

void Wallet::UpgradeDatabase()
{
    std::array<std::string, 3> tables = {
        "CREATE TABLE IF NOT EXISTS 'terms' ("
            "'id' INTEGER PRIMARY KEY NOT NULL,"
            "'body' TEXT UNIQUE NOT NULL,"
            "'timestamp' INTEGER NOT NULL);",
        "CREATE TABLE IF NOT EXISTS 'output' ("
            "'id' INTEGER PRIMARY KEY NOT NULL,"
            "'timestamp' INTEGER NOT NULL,"
            "'hash' BLOB NOT NULL,"
            "'secret_id' INTEGER,"
            "'amount' INTEGER NOT NULL,"
            "'spent' INTEGER NOT NULL,"
            "FOREIGN KEY('secret_id') REFERENCES 'secret'('id'));",
        "CREATE TABLE IF NOT EXISTS 'secret' ("
            "'id' INTEGER PRIMARY KEY NOT NULL,"
            "'timestamp' INTEGER NOT NULL,"
            "'secret' TEXT UNIQUE NOT NULL,"
            "'mine' INTEGER NOT NULL,"
            "'sweep' INTEGER NOT NULL);",
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

bool Wallet::Insert(const SecretWebcash& sk, bool mine)
{
    using std::to_string;
    const std::lock_guard<std::mutex> lock(m_mut);
    bool result = true;

    // The database records
    const int64_t now = absl::ToUnixSeconds(absl::Now());

    // First write the key to the wallet recovery file
    {
        std::string line = absl::StrCat(to_string(now), " ", mine ? "mining" : "receive", " ", to_string(sk));
        boost::filesystem::ofstream bak(m_logfile.string(), boost::filesystem::ofstream::app);
        if (!bak) {
            std::cerr << "WARNING: Unable to open/create wallet recovery file to save key prior to insertion: \"" << line << "\".  BACKUP THIS KEY NOW TO AVOID DATA LOSS!" << std::endl;
            // We do not return false here even though there was an error writing to
            // the recovery log, because we can still attempt to save the key to the
            // wallet.
            result = false;
        } else {
            bak << line << std::endl;
            bak.flush();
        }
    }

    // Then attempt to write the key to the wallet database
    const std::string stmt = "INSERT INTO 'secret' ('timestamp', 'secret', 'mine', 'sweep') VALUES(?, ?, ?, ?);";
    sqlite3_stmt* insert;
    int res = sqlite3_prepare_v2(m_db, stmt.c_str(), stmt.size(), &insert, nullptr);
    if (res != SQLITE_OK) {
        std::cerr << "Unable to prepare SQL statement [\"" << stmt << "\"]: " << sqlite3_errstr(res) << " (" << to_string(res) << ")" << std::endl;
        return false;
    }
    res = sqlite3_bind_int64(insert, 1, now);
    if (res != SQLITE_OK) {
        std::cerr << "Unable to bind 'timestamp' in SQL statement [\"" << stmt << "\"] to " << to_string(now) << ": " << sqlite3_errstr(res) << " (" << to_string(res) << ")";
        sqlite3_finalize(insert);
        return false;
    }
    const std::string secret_hex = absl::BytesToHexString(sk.sk);
    res = sqlite3_bind_text(insert, 2, secret_hex.c_str(), secret_hex.size(), SQLITE_STATIC);
    if (res != SQLITE_OK) {
        std::cerr << "Unable to bind 'secret' in SQL statement [\"" << stmt << "\"] to x'" << absl::BytesToHexString(sk.sk) << "': " << sqlite3_errstr(res) << " (" << to_string(res) << ")" << std::endl;
        sqlite3_finalize(insert);
        return false;
    }
    res = sqlite3_bind_int(insert, 3, !!mine);
    if (res != SQLITE_OK) {
        std::cerr << "Unable to bind 'mine' in SQL statement [\"" << stmt << "\"] to " << (mine ? "TRUE" : "FALSE") << ": " << sqlite3_errstr(res) << " (" << to_string(res) << ")";
        sqlite3_finalize(insert);
        return false;
    }
    res = sqlite3_bind_int(insert, 4, !!true);
    if (res != SQLITE_OK) {
        std::cerr << "Unable to bind 'sweep' in SQL statement [\"" << stmt << "\"] to TRUE: " << sqlite3_errstr(res) << " (" << to_string(res) << ")";
        sqlite3_finalize(insert);
        return false;
    }
    res = sqlite3_step(insert);
    if (res != SQLITE_DONE) {
        std::cerr << "Running SQL statement [\"" << sqlite3_expanded_sql(insert) << "\"] returned unexpected status code: " << sqlite3_errstr(res) << " (" << to_string(res) << ")" << std::endl;
        sqlite3_finalize(insert);
        return false;
    }
    int secret_id = sqlite3_last_insert_rowid(m_db);
    sqlite3_finalize(insert); insert = nullptr;

    // And then write the output record
    const std::string stmt2 = "INSERT INTO 'output' ('timestamp', 'hash', 'secret_id', 'amount', 'spent') VALUES(?, ?, ?, ?, ?);";
    PublicWebcash pk(sk);
    res = sqlite3_prepare_v2(m_db, stmt2.c_str(), stmt2.size(), &insert, nullptr);
    if (res != SQLITE_OK) {
        std::cerr << "Unable to prepare SQL statement [\"" << stmt2 << "\"]: " << sqlite3_errstr(res) << " (" << to_string(res) << ")" << std::endl;
        return false;
    }
    res = sqlite3_bind_int64(insert, 1, now);
    if (res != SQLITE_OK) {
        std::cerr << "Unable to bind 'timestamp' in SQL statement [\"" << stmt2 << "\"] to " << to_string(now) << ": " << sqlite3_errstr(res) << " (" << to_string(res) << ")" << std::endl;
        sqlite3_finalize(insert);
        return false;
    }
    res = sqlite3_bind_blob(insert, 2, pk.pk.begin(), 32, SQLITE_STATIC);
    if (res != SQLITE_OK) {
        std::cerr << "Unable to bind 'hash' in SQL statement [\"" << stmt2 << "\"] to x'" << absl::BytesToHexString(absl::string_view((const char*)pk.pk.begin(), 32)) << "': " << sqlite3_errstr(res) << " (" << to_string(res) << ")" << std::endl;
        sqlite3_finalize(insert);
        return false;
    }
    res = sqlite3_bind_int(insert, 3, secret_id);
    if (res != SQLITE_OK) {
        std::cerr << "Unable to bind 'secret_id' in SQL statement [\"" << stmt2 << "\"] to " << to_string(secret_id) << ": " << sqlite3_errstr(res) << " (" << to_string(res) << ")" << std::endl;
        sqlite3_finalize(insert);
        return false;
    }
    res = sqlite3_bind_int64(insert, 4, pk.amount.i64);
    if (res != SQLITE_OK) {
        std::cerr << "Unable to bind 'amount' in SQL statement [\"" << stmt2 << "\"] to " << to_string(pk.amount.i64) << ": " << sqlite3_errstr(res) << " (" << to_string(res) << ")" << std::endl;
        sqlite3_finalize(insert);
        return false;
    }
    res = sqlite3_bind_int(insert, 5, !!false);
    if (res != SQLITE_OK) {
        std::cerr << "Unable to bind 'spent' in SQL statement [\"" << stmt2 << "\"] to FALSE: " << sqlite3_errstr(res) << " (" << to_string(res) << ")" << std::endl;
        sqlite3_finalize(insert);
        return false;
    }
    res = sqlite3_step(insert);
    if (res != SQLITE_DONE) {
        std::cerr << "Running SQL statement [\"" << sqlite3_expanded_sql(insert) << "\"] returned unexpected status code: " << sqlite3_errstr(res) << " (" << to_string(res) << ")" << std::endl;
        result = false;
    }
    sqlite3_finalize(insert);

    return result;
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
