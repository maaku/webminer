// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "server.h"

#include <stdint.h>

#include <atomic>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "absl/numeric/int128.h"

#include "absl/time/clock.h"
#include "absl/time/time.h"

#include <drogon/HttpController.h>
#include <drogon/HttpSimpleController.h>
#include <drogon/orm/Exception.h>

#include <json/json.h>

#include "uint256.h"
#include "webcash.h"

using std::to_string;

using drogon::HttpController;
using drogon::HttpSimpleController;
using drogon::HttpRequest;
using drogon::HttpRequestPtr;
using drogon::HttpResponse;
using drogon::HttpResponsePtr;
using drogon::orm::DbClient;
using drogon::orm::DrogonDbException;
using drogon::orm::Result;
using drogon::orm::Transaction;

using Json::ValueType::nullValue;
using Json::ValueType::objectValue;

namespace webcash {
static void _upgradeDb()
{
    const std::array<std::string, 6> create_tables = {
        "CREATE TABLE IF NOT EXISTS \"MiningReports\"("
            "\"id\" BIGSERIAL PRIMARY KEY NOT NULL,"
            "\"received\" BIGINT NOT NULL,"
            "\"preimage\" TEXT UNIQUE NOT NULL,"
            "\"difficulty\" SMALLINT NOT NULL,"
            "\"next_difficulty\" SMALLINT NOT NULL,"
            "\"aggregate_work\" DOUBLE PRECISION NOT NULL)",
        "CREATE TABLE IF NOT EXISTS \"Replacements\"("
            "\"id\" BIGSERIAL PRIMARY KEY NOT NULL,"
            "\"received\" BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS \"ReplacementInputs\"("
            "\"id\" BIGSERIAL PRIMARY KEY NOT NULL,"
            "\"replacement_id\" BIGINT NOT NULL,"
            "\"hash\" BYTEA NOT NULL,"
            "\"amount\" BIGINT NOT NULL,"
            "FOREIGN KEY(\"replacement_id\") REFERENCES \"Replacements\"(\"id\"),"
            "UNIQUE(\"hash\", \"replacement_id\"))",
        "CREATE TABLE IF NOT EXISTS \"ReplacementOutputs\"("
            "\"id\" BIGSERIAL PRIMARY KEY NOT NULL,"
            "\"replacement_id\" BIGINT NOT NULL,"
            "\"hash\" BYTEA NOT NULL,"
            "\"amount\" BIGINT NOT NULL,"
            "FOREIGN KEY(\"replacement_id\") REFERENCES \"Replacements\"(\"id\"),"
            "UNIQUE(\"hash\", \"replacement_id\"))",
        "CREATE TABLE IF NOT EXISTS \"UnspentOutputs\"("
            "\"id\" BIGSERIAL PRIMARY KEY NOT NULL,"
            "\"hash\" BYTEA UNIQUE NOT NULL,"
            "\"amount\" BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS \"SpentHashes\"(" // FIXME: This should eventually
            "\"id\" BIGSERIAL PRIMARY KEY NOT NULL,"  //        be moved to redis?
            "\"hash\" BYTEA UNIQUE NOT NULL)",
    };
    auto db = drogon::app().getDbClient();
    assert(db);
    for (const std::string& sql : create_tables) {
        try {
            db->execSqlSync(sql);
        } catch (const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << sql << std::endl;
            drogon::app().quit();
        }
    }
    {
        static const std::string sql = "SELECT COUNT(1) FROM \"MiningReports\"";
        try {
            const Result r = db->execSqlSync(sql);
            if (r.empty() || !r[0].size()) {
                std::cerr << "error: Expected one row of one column containing count.  Got something else." << std::endl;
                std::cerr << "error: Offending SQL: " << sql << std::endl;
                drogon::app().quit();
            }
            unsigned num_reports = r[0][0].as<unsigned>();
            if (webcash::state().logging) {
                std::stringstream ss;
                ss << "Loaded " << num_reports << " mining reports." << std::endl;
                std::cout << ss.str();
            }
            webcash::state().num_reports.store(num_reports);
        } catch (const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << sql << std::endl;
            drogon::app().quit();
        }
    }
    {
        static const std::string sql = "SELECT COUNT(1) FROM \"Replacements\"";
        try {
            const Result r = db->execSqlSync(sql);
            if (r.empty() || !r[0].size()) {
                std::cerr << "error: Expected one row of one column containing count.  Got something else." << std::endl;
                std::cerr << "error: Offending SQL: " << sql << std::endl;
                drogon::app().quit();
            }
            unsigned num_replace = r[0][0].as<unsigned>();
            if (webcash::state().logging) {
                std::stringstream ss;
                ss << "Loaded " << num_replace << " transactions." << std::endl;
                std::cout << ss.str();
            }
            webcash::state().num_replace.store(num_replace);
        } catch (const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << sql << std::endl;
            drogon::app().quit();
        }
    }
    {
        static const std::string sql = "SELECT COUNT(1) FROM \"UnspentOutputs\"";
        try {
            const Result r = db->execSqlSync(sql);
            if (r.empty() || !r[0].size()) {
                std::cerr << "error: Expected one row of one column containing count.  Got something else." << std::endl;
                std::cerr << "error: Offending SQL: " << sql << std::endl;
                drogon::app().quit();
            }
            unsigned num_unspent = r[0][0].as<unsigned>();
            if (webcash::state().logging) {
                std::stringstream ss;
                ss << "Loaded " << num_unspent << " unspent webcash." << std::endl;
                std::cout << ss.str();
            }
            webcash::state().num_unspent.store(num_unspent);
        } catch (const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << sql << std::endl;
            drogon::app().quit();
        }
    }
    {
        static const std::string sql = "SELECT \"received\" FROM \"MiningReports\" ORDER BY \"id\" ASC LIMIT 1";
        try {
            const Result r = db->execSqlSync(sql);
            absl::Time genesis = webcash::state().genesis; // default value
            if (!r.empty() && r[0].size()) {
                genesis = absl::FromUnixNanos(r[0][0].as<uint64_t>());
            }
            if (webcash::state().logging) {
                std::stringstream ss;
                ss << "Genesis epoch is " << absl::FormatTime(genesis, absl::UTCTimeZone()) << std::endl;
                std::cout << ss.str();
            }
            webcash::state().genesis = genesis;
        } catch (const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << sql << std::endl;
            drogon::app().quit();
        }
    }
    {
        static const std::string sql = "SELECT \"next_difficulty\" FROM \"MiningReports\" ORDER BY \"id\" DESC LIMIT 1";
        try {
            const Result r = db->execSqlSync(sql);
            unsigned difficulty = webcash::state().difficulty.load(); // default value
            if (!r.empty() && r[0].size()) {
                difficulty = r[0][0].as<unsigned>();
            }
            if (webcash::state().logging) {
                std::stringstream ss;
                ss << "Current difficulty is " << difficulty << std::endl;
                std::cout << ss.str();
            }
            webcash::state().difficulty.store(difficulty);
        } catch (const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << sql << std::endl;
            drogon::app().quit();
        }
    }
}
void upgradeDb()
{
    drogon::app().getLoop()->queueInLoop([]() {
        _upgradeDb();
    });
}

static void _resetDb()
{
    const std::array<std::string, 6> drop_tables = {
        "DROP TABLE IF EXISTS \"SpentHashes\"",
        "DROP TABLE IF EXISTS \"UnspentOutputs\"",
        "DROP TABLE IF EXISTS \"ReplacementOutputs\"",
        "DROP TABLE IF EXISTS \"ReplacementInputs\"",
        "DROP TABLE IF EXISTS \"Replacements\"",
        "DROP TABLE IF EXISTS \"MiningReports\"",
    };
    auto db = drogon::app().getDbClient();
    // Drop tables from database
    for (const std::string& sql : drop_tables) {
        try {
            db->execSqlSync(sql);
        } catch (const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << sql << std::endl;
            drogon::app().quit();
        }
    }
    // Re-create (empty) tables and load defaults
    _upgradeDb();
}
void resetDb()
{
    drogon::app().getLoop()->queueInLoop([]() {
        if (webcash::state().logging) {
            std::stringstream ss;
            ss << "Nuking database with "
               << webcash::state().num_reports.load() << " mining reports, "
               << webcash::state().num_replace.load() << " replacements, and "
               << webcash::state().num_unspent.load() << " unspent outputs." << std::endl;
            std::cout << ss.str();
        }
        _resetDb();
    });
}
} // webcash

WebcashStats WebcashEconomy::getStats(absl::Time now)
{
    WebcashStats stats;
    stats.timestamp = now;
    do {
        stats.num_reports = num_reports.load();
        stats.difficulty = difficulty.load();
    } while (stats.num_reports != num_reports.load());

    // There is a potential race condition in accessing these fields.  We could
    // do the loop like we do above, but with replacements coming in much more
    // frequently than mining reports, this has the potential to get threads
    // stuck in an "infinte" loop.  Instead we just accept that these numbers
    // might not be precisely accurate to each other.
    stats.num_replace = num_replace.load();
    stats.num_unspent = num_unspent.load();

    stats.total_circulation = 0;
    auto count = stats.num_reports;
    int64_t value = k_initial_mining_amount;
    while (k_reports_per_epoch < count) {
        stats.total_circulation += value * k_reports_per_epoch;
        count -= k_reports_per_epoch;
    }
    stats.total_circulation += count * value;

    stats.expected_circulation = 0;
    count = static_cast<unsigned>((stats.timestamp - genesis) / k_target_interval);
    value = k_initial_mining_amount;
    while (k_reports_per_epoch < count) {
        stats.expected_circulation += value * k_reports_per_epoch;
        count -= k_reports_per_epoch;
    }
    stats.expected_circulation += count * value;

    // Do not use the class methods because that would re-fetch num_reports,
    // which might have been updated.
    stats.epoch = stats.num_reports / k_reports_per_epoch;
    if (stats.epoch > 63) {
        stats.mining_amount = 0;
        stats.subsidy_amount = 0;
    } else {
        stats.mining_amount = k_initial_mining_amount >> stats.epoch;
        stats.subsidy_amount = k_initial_subsidy_amount >> stats.epoch;
    }

    return stats;
}

namespace webcash {
    WebcashEconomy& state()
    {
        static WebcashEconomy economy;
        return economy;
    }
} // webcash

std::shared_ptr<HttpResponse> JSONRPCError(const std::string& err)
{
    Json::Value ret(objectValue);
    ret["status"] = "error";
    // FIXME: In the case of /mining_report, we need to somehow get the
    //        difficulty in here.
    if (!err.empty()) {
        ret["error"] = err;
    } else {
        ret["error"] = "unknown";
    }
    auto resp = HttpResponse::newHttpJsonResponse(ret);
    resp->setStatusCode(drogon::k500InternalServerError);
    return resp;
}

bool check_legalese(
    const Json::Value& request
){
    if (!request.isObject())
        return false;
    if (!request.isMember("legalese"))
        return false;
    const auto& legalese = request["legalese"];
    if (!legalese.isObject())
        return false;
    if (!legalese.isMember("terms"))
        return false;
    const auto& terms = legalese["terms"];
    if (!terms.isConvertibleTo(Json::booleanValue))
        return false;
    return terms.asBool();
}

bool parse_secret_webcashes(
    const Json::Value& array,
    std::map<uint256, SecretWebcash>& _webcash
){
    _webcash.clear();
    std::map<uint256, SecretWebcash> webcash;
    if (!array.isArray()) {
        return false; // expected array
    }
    for (unsigned int i = 0; i < array.size(); ++i) {
        auto& secret_str = array[i];
        if (!secret_str.isString()) {
            return false; // must be string-encoded
        }
        SecretWebcash secret;
        if (!secret.parse(secret_str.asString())) {
            return false; // parser error
        }
        PublicWebcash pub(secret);
        auto res = webcash.insert({pub.pk, secret});
        if (!res.second) {
            return false; // duplicate
        }
    }
    if (webcash.size() != array.size()) {
        return false; // duplicate
    }
    _webcash.swap(webcash);
    return true;
}

bool parse_public_webcashes(
    const Json::Value& array,
    std::vector<PublicWebcash>& _webcash
){
    _webcash.clear();
    std::vector<PublicWebcash> webcash;
    if (!array.isArray()) {
        return false; // expected array
    }
    for (unsigned int i = 0; i < array.size(); ++i) {
        auto& descriptor_str = array[i];
        if (!descriptor_str.isString()) {
            return false; // must be string-encoded
        }
        PublicWebcash descriptor;
        if (!descriptor.parse(descriptor_str.asString())) {
            return false; // parser error
        }
        webcash.push_back(descriptor);
    }
    if (webcash.size() != array.size()) {
        return false; // duplicate
    }
    _webcash.swap(webcash);
    return true;
}

//  -------------
// | /terms      |
// | /terms/text |
//  -------------

void TermsOfService::asyncHandleHttpRequest(
    const HttpRequestPtr& req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    HttpResponsePtr resp;
    if (req && req->getPath() == "/terms") {
        resp = HttpResponse::newFileResponse("terms/terms.html", "", drogon::CT_TEXT_HTML);
        resp->setExpiredTime(k_terms_cache_expiry);
    }
    else if (req && req->getPath() == "/terms/text") {
        resp = HttpResponse::newFileResponse("terms/terms.text", "", drogon::CT_TEXT_PLAIN);
        resp->setExpiredTime(k_terms_cache_expiry);
    } else {
        // If we get here, our view controller is messed up.
        // Check the path definitions.
        resp = HttpResponse::newNotFoundResponse();
    }
    callback(resp);
}

namespace api {

//  -----------------
// | /api/v1/replace |
//  -----------------

// Nobody loves writing asynchronous code, and reading it is even worse.  I've
// tried to decrease the burden here by laying things out in a logical
// progression, keeping the code as linear as possible.
//
// As we go through the process of validating a replacement, all the
// intermediate state needed is kept in a shared pointer to a ReplacementState
// structure.  Reference-counted shared pointers are used so that when the
// request is finished the intermediate state will naturally be cleaned up.
// This structure is, as much as possible, filled out before a connection to the
// database is made, so that precious time isn't spent allocating memory or
// parsing fields while locks are held on tables or rows in the database.
struct ReplacementState {
    // The actual replacement request from the caller.
    std::shared_ptr<Json::Value> msg;
    // The system clock time when the replace request was received by us.
    absl::Time received = absl::UnixEpoch();
    // The input and output webcash secrets, as provided by the caller.
    std::map<uint256, SecretWebcash> inputs;
    std::map<uint256, SecretWebcash> outputs;
    // A straight summation over the inputs and outputs.
    Amount total_in = Amount{0};
    Amount total_out = Amount{0};
    // Pre-constructed SQL statements.
    std::string sql_check_inputs;
    std::string sql_check_outputs;
    std::string sql_store_spends;
    std::string sql_delete_inputs;
    std::string sql_insert_outputs;
    std::string sql_audit_log_inputs;
    std::string sql_audit_log_outputs;
    // The primary key of the Replacements record for the audit log.  Used to
    // create records in the ReplacementInputs and ReplacementOutputs
    // one-to-many join tables.
    uint64_t replacement_id = 0;
};

// Once a request is received, it is passed through a sequence of functions,
// each of which initiates a call to the database and does something with the
// results.  Since we want the processing of a replaement to be ACID, we pass a
// shared pointer to a database transaction object which used to interact with
// the database.  tx->rollback() is used if any error is encountered, which
// terminates the replacement request and prevents further procesing.
void CheckInputsExist(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx); // Calls CheckOutputsDoNotExist...

void CheckOutputsDoNotExist(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx); // Calls RecordSpends...

void RecordSpends(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx); // etc.

void RemoveInputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx);

void CreateOutputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx);

void RecordToAuditLog(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx);

void RecordToAuditLogInputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx);

void RecordToAuditLogOutputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx);

void ReportReplacement(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx); // Done

void V1::replace(
    const HttpRequestPtr &req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    absl::Time _received = absl::Now();
    auto state = std::make_shared<ReplacementState>();
    state->received = _received;

    state->msg = req->getJsonObject();
    if (!state->msg || !state->msg->isObject()) {
        return callback(JSONRPCError("no JSON body"));
    }
    if (!check_legalese(*state->msg)) {
        return callback(JSONRPCError("didn't accept terms"));
    }

    // Extract 'inputs'
    if (!state->msg->isMember("webcashes")) {
        return callback(JSONRPCError("no inputs"));
    }
    if (!parse_secret_webcashes((*state->msg)["webcashes"], state->inputs)) {
        return callback(JSONRPCError("can't parse inputs"));
    }
    state->total_in = Amount(0);
    std::vector<std::string> input_values_hash_with_amount;
    std::vector<std::string> input_values_hash_only;
    input_values_hash_with_amount.reserve(state->inputs.size());
    input_values_hash_only.reserve(state->inputs.size());
    for (const auto& item : state->inputs) {
        const uint256& hash = item.first;
        const SecretWebcash& wc = item.second;
        state->total_in += wc.amount;
        if (state->total_in < 1 || wc.amount < 1) {
            return callback(JSONRPCError("overflow"));
        }
        std::string hash_hex = absl::BytesToHexString(absl::string_view((char*)hash.data(), 32));
        input_values_hash_with_amount.push_back(absl::StrCat("('\\x", hash_hex, "'::bytea,", to_string(wc.amount.i64), ")"));
        input_values_hash_only.push_back(absl::StrCat("('\\x", hash_hex, "'::bytea)"));
    }

    // Extract 'outputs'
    if (!state->msg->isMember("new_webcashes")) {
        return callback(JSONRPCError("no outputs"));
    }
    if (!parse_secret_webcashes((*state->msg)["new_webcashes"], state->outputs)) {
        return callback(JSONRPCError("can't parse inputs"));
    }
    state->total_out = Amount(0);
    std::vector<std::string> output_values_hash_with_amount;
    std::vector<std::string> output_values_hash_only;
    output_values_hash_with_amount.reserve(state->outputs.size());
    output_values_hash_only.reserve(state->outputs.size());
    for (const auto& item : state->outputs) {
        const uint256& hash = item.first;
        const SecretWebcash& wc = item.second;
        state->total_out += wc.amount;
        if (state->total_out < 1 || wc.amount < 1) {
            return callback(JSONRPCError("overflow"));
        }
        std::string hash_hex = absl::BytesToHexString(absl::string_view((char*)hash.data(), 32));
        output_values_hash_with_amount.push_back(absl::StrCat("('\\x", hash_hex, "'::bytea,", to_string(wc.amount.i64), ")"));
        output_values_hash_only.push_back(absl::StrCat("('\\x", hash_hex, "'::bytea)"));
    }

    // Check inputs == outputs
    if (state->total_in != state->total_out) {
        return callback(JSONRPCError("inbalance"));
    }

    // Prepare SQL statements
    state->sql_check_inputs = absl::StrCat("WITH \"InputHashAmount\"(\"hash\",\"amount\") AS (VALUES", absl::StrJoin(input_values_hash_with_amount, ","), ") SELECT COUNT(1) FROM \"UnspentOutputs\" INNER JOIN \"InputHashAmount\" ON \"UnspentOutputs\".\"hash\"=\"InputHashAmount\".\"hash\" AND \"UnspentOutputs\".\"amount\"=\"InputHashAmount\".\"amount\"");
    state->sql_check_outputs = absl::StrCat("SELECT COUNT(1) FROM \"UnspentOutputs\" WHERE \"hash\" IN (", absl::StrJoin(output_values_hash_only, ","), ")");
    state->sql_store_spends = absl::StrCat("INSERT INTO \"SpentHashes\" (\"hash\") VALUES", absl::StrJoin(input_values_hash_only, ","), "ON CONFLICT DO NOTHING");
    state->sql_delete_inputs = absl::StrCat("DELETE FROM \"UnspentOutputs\" WHERE \"hash\" IN (SELECT * FROM (VALUES", absl::StrJoin(input_values_hash_only, ","), ") AS hashes)");
    state->sql_insert_outputs = absl::StrCat("INSERT INTO \"UnspentOutputs\" (\"hash\", \"amount\") VALUES", absl::StrJoin(output_values_hash_with_amount, ","));
    state->sql_audit_log_inputs = absl::StrCat("INSERT INTO \"ReplacementInputs\" (\"replacement_id\", \"hash\", \"amount\") SELECT $1, * FROM (VALUES", absl::StrJoin(input_values_hash_with_amount, ","), ") AS inputs");
    state->sql_audit_log_outputs = absl::StrCat("INSERT INTO \"ReplacementOutputs\" (\"replacement_id\", \"hash\", \"amount\") SELECT $1, * FROM (VALUES", absl::StrJoin(output_values_hash_with_amount, ","), ") AS outputs");

    // Now we perform checks that require access to global state.
    auto db = drogon::app().getDbClient();
    if (!db) {
        return callback(JSONRPCError("error getting connection to database"));
    }
    auto tx = db->newTransaction();
    if (!db) {
        return callback(JSONRPCError("error creating database transaction"));
    }

    return CheckInputsExist(callback, state, tx);
}

void CheckInputsExist(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx
){
    *tx << state->sql_check_inputs
        >> [=](const Result &r) {
            if (r.empty() || !r[0].size()) {
                std::cerr << "error: Expected one row of one column containing count.  Got something else." << std::endl;
                std::cerr << "error: Offending SQL: " << state->sql_check_inputs << std::endl;
                tx->rollback();
                return callback(JSONRPCError("sql error"));
            }

            unsigned found = r[0][0].as<unsigned>();
            if (found != state->inputs.size()) {
                std::cerr << "error: One or more specified input values not found in database." << std::endl;
                std::cerr << "error: only " << to_string(found) << " of " << to_string(state->inputs.size()) << " inputs are valid." << std::endl;
                tx->rollback();
                return callback(JSONRPCError("input(s) not found"));
            }

            return CheckOutputsDoNotExist(callback, state, tx);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << state->sql_check_inputs << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void CheckOutputsDoNotExist(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx
){
    *tx << state->sql_check_outputs
        >> [=](const Result &r) {
            if (r.empty() || !r[0].size()) {
                std::cerr << "error: Expected one row of one column containing count.  Got something else." << std::endl;
                std::cerr << "error: Offending SQL: " << state->sql_check_outputs << std::endl;
                tx->rollback();
                return callback(JSONRPCError("sql error"));
            }

            unsigned found = r[0][0].as<unsigned>();
            if (found) {
                std::cerr << "error: Replacement contains existing output.  Cowardly refusing to overwrite." << std::endl;
                std::cerr << "error: " << to_string(found) << " outputs already exist." << std::endl;
                tx->rollback();
                return callback(JSONRPCError("output(s) already exists"));
            }

            return RecordSpends(callback, state, tx);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << state->sql_check_outputs << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void RecordSpends(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx
){
    *tx << state->sql_store_spends
        >> [=](const Result &r) {
            RemoveInputs(callback, state, tx);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << state->sql_store_spends << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void RemoveInputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx
){
    *tx << state->sql_delete_inputs
        >> [=](const Result &r) {
            CreateOutputs(callback, state, tx);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << state->sql_delete_inputs << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void CreateOutputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx
){
    *tx << state->sql_insert_outputs
        >> [=](const Result &r) {
            RecordToAuditLog(callback, state, tx);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << state->sql_insert_outputs << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void RecordToAuditLog(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx
){
    static const std::string sql = absl::StrCat("INSERT INTO \"Replacements\" (\"received\") VALUES($1) RETURNING \"id\"");
    *tx << sql
        << absl::ToUnixNanos(state->received)
        >> [=](const Result &r) {
            if (r.empty() || !r[0].size() || !(state->replacement_id = r[0][0].as<uint64_t>())) {
                std::cerr << "error: Expected one row of one column containing inserted id.  Got something else." << std::endl;
                std::cerr << "error: Offending SQL: " << state->sql_check_outputs << std::endl;
                tx->rollback();
                return callback(JSONRPCError("sql error"));
            }
            RecordToAuditLogInputs(callback, state, tx);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << sql << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void RecordToAuditLogInputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx
){
    *tx << state->sql_audit_log_inputs
        << state->replacement_id
        >> [=](const Result &r) {
            RecordToAuditLogOutputs(callback, state, tx);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << state->sql_audit_log_inputs << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void RecordToAuditLogOutputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx
){
    *tx << state->sql_audit_log_outputs
        << state->replacement_id
        >> [=](const Result &r) {
            ReportReplacement(callback, state, tx);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << state->sql_audit_log_outputs << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void ReportReplacement(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<ReplacementState> state,
    std::shared_ptr<Transaction> tx
){
    tx->setCommitCallback([=](bool){
        // Note that while each of these updates are atomic, the combination is
        // not.  It is possible for a read of the field to occur inbetween the
        // statements.  At this time this field is informational only, so that
        // is not a concern.
        ++(webcash::state().num_replace);
        webcash::state().num_unspent += state->outputs.size();
        webcash::state().num_unspent -= state->inputs.size();

        if (webcash::state().logging) {
            std::stringstream ss;
            ss << "Replaced " << state->inputs.size()
               << " input for " << state->outputs.size()
               << " output (total: ₩" << to_string(state->total_in) << ")."
               << " tx=" << webcash::state().num_replace.load()
               << " unspent=" << webcash::state().num_unspent.load()
               << std::endl;
            std::cout << ss.str();
        }

        Json::Value ret(objectValue);
        ret["status"] = "success";
        auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
        return callback(resp);
    });
}

//  ----------------
// | /api/v1/target |
//  ----------------

void V1::target(
    const HttpRequestPtr &req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    WebcashStats stats = webcash::state().getStats(absl::Now());

    Json::Value ret(objectValue);
    ret["difficulty_target_bits"] = stats.difficulty;
    ret["epoch"] = static_cast<int>(stats.epoch);
    ret["mining_amount"] = to_string(stats.mining_amount);
    ret["mining_subsidy_amount"] = to_string(stats.subsidy_amount);
    if (stats.total_circulation > 0 && stats.expected_circulation > 0) {
        ret["ratio"] = static_cast<double>(stats.total_circulation) / static_cast<double>(stats.expected_circulation);
    } else {
        ret["ratio"] = 1.0; // To avoid transient errors on startup
    }

    auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
    resp->setExpiredTime(k_target_cache_expiry);
    callback(resp);
}

//  -----------------------
// | /api/v1/mining_report |
//  -----------------------

// Contains intermediate state for processing a MiningReport submission request.
struct MiningReportState {
    // The system clock time at which the request was received.
    absl::Time received;
    // The base64-encoded mining report as received from the caller.
    std::string preimage;
    // The sha256 hash of the preimage. (cached)
    uint256 hash;
    // The actual number of leading zero bits of the hash. (cached)
    unsigned bits;
    // If the parsed preimage contains a "difficulty" field, and its value.
    bool has_difficulty = false;
    unsigned difficulty = 0;
    // If the parsed preimage contains a "timestamp" field, and its value.
    bool has_timestamp = false;
    absl::Time timestamp = absl::UnixEpoch();
    // The "webcash" and "subsidy" fields of the preimage, indexed by public hash.
    std::map<uint256, SecretWebcash> webcash;
    std::map<uint256, SecretWebcash> subsidy;
    // The calculated sum of the webcash and subsidy arrays. (cached)
    Amount webcash_sum = Amount{0};
    Amount subsidy_sum = Amount{0};
    // Pre-constructed SQL statements.
    std::vector<uint256> to_check;
    std::string sql_check_outputs;
    std::string sql_insert_outputs;
    // The fields of the last MiningReport received by the server, which is
    // needed for difficulty adjustment and calculating this report's aggregate
    // fields.  Obviosuly these values can't be known until the transaction is
    // started.
    bool has_last_report = false;
    unsigned num_reports = 0;
    absl::Time last_received = absl::UnixEpoch();
    unsigned last_difficulty = 0;
    unsigned current_difficulty = 0;
    double last_aggregate_work = 0.0;
};

// The async function for validating and recording a mining report.  Each
// function takes the state as input, and makes an asynchronous call to the
// database.  It then processes the results and calls the next function in
// sequence.
void SelectLastMiningReport(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<MiningReportState> state,
    std::shared_ptr<Transaction> tx); // Calls CheckNewMiningReportPreimage...

void CheckNewMiningReportPreimage(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<MiningReportState> state,
    std::shared_ptr<Transaction> tx); // Calls CheckOutputsDoNotExist...

void CheckOutputsDoNotExist(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<MiningReportState> state,
    std::shared_ptr<Transaction> tx); // etc.

void CreateOutputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<MiningReportState> state,
    std::shared_ptr<Transaction> tx);

void RecordMiningReport(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<MiningReportState> state,
    std::shared_ptr<Transaction> tx);

void ReportSolution(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<MiningReportState> state,
    std::shared_ptr<Transaction> tx); // Done

void V1::miningReport(
    const HttpRequestPtr &req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    absl::Time _received = absl::Now();
    auto state = std::make_shared<MiningReportState>();
    state->received = _received;

    auto maybe_msg = req->getJsonObject();
    if (!maybe_msg || !maybe_msg->isObject()) {
        return callback(JSONRPCError("no JSON body"));
    }
    auto msg = *maybe_msg;
    if (!check_legalese(msg)) {
        return callback(JSONRPCError("didn't accept terms"));
    }

    // Extract base64-encoded preimage
    if (!msg.isMember("preimage") || !msg["preimage"].isString()) {
        return callback(JSONRPCError("missing preimage"));
    }
    state->preimage = msg["preimage"].asString();
    std::string preimage_str;
    if (!absl::Base64Unescape(state->preimage, &preimage_str)) {
        return callback(JSONRPCError("preimage is not base64-encoded string"));
    }

    Json::CharReaderBuilder builder {};
    auto reader = std::unique_ptr<Json::CharReader>(builder.newCharReader());
    Json::Value preimage;
    std::string errors;
    if (!reader->parse(preimage_str.c_str(), preimage_str.c_str() + preimage_str.length(), &preimage, &errors)) {
        return callback(JSONRPCError("couldn't parse preimage as JSON"));
    }

    // Read 'webcash', the array of webcash claim codes generated by this miner.
    if (!preimage.isMember("webcash")) {
        return callback(JSONRPCError("missing 'webcash' field in preimage"));
    }
    if (!parse_secret_webcashes(preimage["webcash"], state->webcash)) {
        return callback(JSONRPCError("'webcash' field in preimage needs to be array of webcash secrets"));
    }

    // Read 'subsidy', the array of webcash claim codes given to the server
    if (!preimage.isMember("subsidy")) {
        return callback(JSONRPCError("missing 'subsidy' field in peimage"));
    }
    if (!parse_secret_webcashes(preimage["subsidy"], state->subsidy)) {
        return callback(JSONRPCError("'subsidy' field in preimage needs to be array of webcash secrets"));
    }

    // Read 'timestamp'
    if (preimage.isMember("timestamp")) {
        if (!preimage["timestamp"].isConvertibleTo(Json::realValue)) {
            return callback(JSONRPCError("'timestamp' field in preimage must be numeric"));
        }
        state->timestamp = absl::FromUnixSeconds(static_cast<int64_t>(preimage["timestamp"].asDouble()));
        state->has_timestamp = true;
    }

    // Read 'difficulty'
    if (preimage.isMember("difficulty")) {
        if (!preimage["difficulty"].isConvertibleTo(Json::uintValue)) {
            return callback(JSONRPCError("'difficulty' field in preimage must be small positive integer"));
        }
        state->difficulty = preimage["difficulty"].asUInt();
        if (state->difficulty > 255) {
            return callback(JSONRPCError("'difficulty' field in preimage is too high"));
        }
        state->has_difficulty = true;
    }

    // Check 'webcash'
    state->webcash_sum = Amount{0};
    std::vector<std::string> output_values_with_amount;
    std::vector<std::string> output_values_hash_only;
    output_values_with_amount.reserve(state->webcash.size());
    output_values_hash_only.reserve(state->webcash.size());
    for (const auto& item : state->webcash) {
        state->webcash_sum += item.second.amount;
        if (state->webcash_sum < 1 || item.second.amount < 1) {
            return callback(JSONRPCError("overflow"));
        }
        const std::string hash_hex = absl::BytesToHexString(absl::string_view((char*)item.first.data(), 32));
        output_values_with_amount.push_back(absl::StrCat("('\\x", hash_hex, "'::bytea,", to_string(item.second.amount.i64), ")"));
        output_values_hash_only.push_back(absl::StrCat("'\\x", hash_hex, "'::bytea"));
    }

    // Check 'subsidy'
    state->subsidy_sum = Amount{0};
    for (const auto& item : state->subsidy) {
        state->subsidy_sum += item.second.amount;
        if (state->subsidy_sum < 1 || item.second.amount < 1) {
            return callback(JSONRPCError("overflow"));
        }
        auto itr = state->webcash.find(item.first);
        if (itr == state->webcash.end()) {
            return callback(JSONRPCError("missing subsidy from webcash"));
        }
        if (itr->second.amount != item.second.amount) {
            return callback(JSONRPCError("subsidy doesn't match webcash"));
        }
    }
    if (state->webcash.size() < state->subsidy.size() || state->webcash_sum < state->subsidy_sum) {
        return callback(JSONRPCError("internal server error")); // should have failed above
    }

    // Check 'timestamp', if present
    if (state->has_timestamp) {
        absl::Time min_time = state->received - absl::Hours(2);
        absl::Time max_time = state->received + absl::Hours(2);
        if (state->timestamp < min_time || max_time < state->timestamp) {
            return callback(JSONRPCError("timestamp of mining report must be within 2 hours of receipt by server"));
        }
    }

    // Calculate proof-of-work
    CSHA256().Write((unsigned char*)state->preimage.c_str(), state->preimage.length()).Finalize(state->hash.data());
    state->bits = get_apparent_difficulty(state->hash);
    if (state->bits < 25) { // DoS prevention
        return callback(JSONRPCError("difficulty too low"));
    }

    // Check 'difficulty', if present
    if (state->has_difficulty) {
        if (state->bits < state->difficulty) {
            return callback(JSONRPCError("proof-of-work doesn't match committed difficulty"));
        }
    }

    // Preconstruct SQL queries.
    state->sql_check_outputs = absl::StrCat("SELECT COUNT(1) FROM \"UnspentOutputs\" WHERE \"hash\" IN (", absl::StrJoin(output_values_hash_only, ","), ")");
    state->sql_insert_outputs = absl::StrCat("INSERT INTO \"UnspentOutputs\" (\"hash\", \"amount\") VALUES", absl::StrJoin(output_values_with_amount, ","));

    // Now we perform checks that require access to global state.
    auto db = drogon::app().getDbClient();
    if (!db) {
        return callback(JSONRPCError("error getting connection to database"));
    }
    auto tx = db->newTransaction();
    if (!db) {
        return callback(JSONRPCError("error creating database transaction"));
    }

    return SelectLastMiningReport(callback, state, tx);
}

void SelectLastMiningReport(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<MiningReportState> state,
    std::shared_ptr<Transaction> tx
){
    static const std::string sql = "SELECT \"received\", \"difficulty\", \"next_difficulty\", \"aggregate_work\" FROM \"MiningReports\" ORDER BY \"id\" DESC LIMIT 1";
    *tx << sql
        >> [=](bool is_null, int64_t received, unsigned difficulty, unsigned next_difficulty, double aggregate_work) {
            if (!is_null) {
                if (state->has_last_report) {
                    std::cerr << "error: More than two rows returned?  Something is very broken." << std::endl;
                    std::cerr << "error: Offending SQL: " << sql << std::endl;
                    tx->rollback();
                    return callback(JSONRPCError("logic error"));
                }
                if (difficulty > 255 || next_difficulty > 255 || aggregate_work < 0.0) {
                    std::cerr << "error: Last MiningReport record contains nonsense values.  Database corruption?" << std::endl;
                    std::cerr << "error: difficulty=" << difficulty << " next_difficulty=" << next_difficulty << " aggregate_work=" << aggregate_work << std::endl;
                    tx->rollback();
                    return callback(JSONRPCError("database error"));
                }
                state->last_received = absl::FromUnixNanos(received);
                state->last_difficulty = difficulty;
                state->current_difficulty = next_difficulty;
                state->last_aggregate_work = aggregate_work;
                state->has_last_report = true;
            } else {
                if (!state->has_last_report) {
                    // No MiningReport records yet, so fill with default
                    // values for the first report.
                    state->last_difficulty = 0;
                    state->current_difficulty = 28;
                    state->last_aggregate_work = 0.0;
                    state->has_last_report = true;
                }

                // Check committed difficulty meets current difficulty
                if (state->has_difficulty && state->difficulty < state->current_difficulty) {
                    std::cerr << "error: Committed difficulty is less than current difficulty." << std::endl;
                    std::cerr << "error: difficulty=" << state->difficulty << " current_difficulty=" << state->current_difficulty << std::endl;
                    tx->rollback();
                    return callback(JSONRPCError("committed difficulty is less than current difficulty"));
                }

                // Check proof-of-work meets difficulty
                if (state->bits < state->current_difficulty) {
                    // Not necessarily an error--perhaps the difficulty changed?
                    std::cerr << "error: Proof of work doesn't meet current difficulty." << std::endl;
                    std::cerr << "error: bits=" << state->bits << " current_difficulty=" << state->current_difficulty << std::endl;
                    tx->rollback();
                    return callback(JSONRPCError("proof of work doesn't meet current difficulty"));
                }

                return CheckNewMiningReportPreimage(callback, state, tx);
            }
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << sql << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void SelectNumMiningReports(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<MiningReportState> state,
    std::shared_ptr<Transaction> tx
){
    static const std::string sql = "SELECT COUNT(1) FROM \"MiningReports\"";
    *tx << sql
        >> [=](const Result& r) {
            if (r.empty() || !r[0].size()) {
                std::cerr << "error: Expected one row of one column containing count.  Got something else." << std::endl;
                std::cerr << "error: Offending SQL: " << sql << std::endl;
                tx->rollback();
                return callback(JSONRPCError("sql error"));
            }

            // Record the number of mining reports for future use.
            state->num_reports = r[0][0].as<unsigned>();
            return CheckNewMiningReportPreimage(callback, state, tx);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << sql << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void CheckNewMiningReportPreimage(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<MiningReportState> state,
    std::shared_ptr<Transaction> tx
){
    static const std::string sql = "SELECT COUNT(1) FROM \"MiningReports\" WHERE \"preimage\"=$1";
    *tx << sql
        << state->preimage
        >> [=](const Result &r) {
            if (r.empty() || !r[0].size()) {
                std::cerr << "error: Expected one row of one column containing count.  Got something else." << std::endl;
                std::cerr << "error: Offending SQL: " << sql << std::endl;
                tx->rollback();
                return callback(JSONRPCError("sql error"));
            }

            if (r[0][0].as<unsigned>()) {
                std::cerr << "error: Received duplicate MiningReport." << std::endl;
                std::cerr << "error: duplicate: " << state->preimage << std::endl;
                tx->rollback();
                return callback(JSONRPCError("reused preimage"));
            }

            // Check outputs sum to expected value
            Amount expected = webcash::state().getMiningAmount(state->num_reports);
            if (state->webcash_sum != expected) {
                std::cerr << "error: Webcash in mining report doesn't sum to expected amount." << std::endl;
                std::cerr << "error: actual=" << to_string(state->webcash_sum) << " expected=" << to_string(expected) << std::endl;
                tx->rollback();
                return callback(JSONRPCError("outputs don't match allowed amount"));
            }

            // Check subsidy sums to expected value
            expected = webcash::state().getSubsidyAmount(state->num_reports);
            if (state->subsidy_sum != expected) {
                std::cerr << "error: Subsidy in mining report doesn't match expected amount." << std::endl;
                std::cerr << "error: actual=" << to_string(state->subsidy_sum) << " expected=" << to_string(expected) << std::endl;
                tx->rollback();
                return callback(JSONRPCError("subsidy doesn't match required amount"));
            }

            return CheckOutputsDoNotExist(callback, state, tx);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << sql << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void CheckOutputsDoNotExist(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<MiningReportState> state,
    std::shared_ptr<Transaction> tx
){
        *tx << state->sql_check_outputs
        >> [=](const Result &r) {
            if (r.empty() || !r[0].size()) {
                std::cerr << "error: Expected one row of one column containing count.  Got something else." << std::endl;
                std::cerr << "error: Offending SQL: " << state->sql_check_outputs << std::endl;
                tx->rollback();
                return callback(JSONRPCError("sql error"));
            }

            unsigned found = r[0][0].as<unsigned>();
            if (found) {
                std::cerr << "error: MiningReport contains existing output.  Cowardly refusing to overwrite." << std::endl;
                std::cerr << "error: " << to_string(found) << " outputs already exist." << std::endl;
                tx->rollback();
                return callback(JSONRPCError("output(s) already exists"));
            }

            state->to_check.clear();
            CreateOutputs(callback, state, tx);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << state->sql_check_outputs << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void CreateOutputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<MiningReportState> state,
    std::shared_ptr<Transaction> tx
){
    *tx << state->sql_insert_outputs
        >> [=](const Result &r) {
            RecordMiningReport(callback, state, tx);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << state->sql_insert_outputs << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void RecordMiningReport(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<MiningReportState> state,
    std::shared_ptr<Transaction> tx
){
    absl::uint128 work = 1;
    work <<= state->current_difficulty;
    double aggregate_work = state->last_aggregate_work + static_cast<double>(work);

    unsigned next_difficulty = state->current_difficulty;
    WebcashStats stats = webcash::state().getStats(state->received);
    unsigned num_reports = stats.num_reports + 1;
    if ((num_reports % WebcashEconomy::k_reports_per_interval) == 0) {
        size_t look_back_window = WebcashEconomy::k_look_back_window;
        if (num_reports == look_back_window) {
            --look_back_window;
        }
        absl::Duration expected = look_back_window * absl::Seconds(10);
        absl::Duration actual = state->received - state->last_received;
        if (actual <= expected && stats.expected_circulation <= stats.total_circulation) {
            // We're early and we're ahead of the issuance curve
            ++next_difficulty;
        }
        if (expected <= actual && stats.total_circulation <= stats.expected_circulation) {
            // We're late and we're behind the issuance curve
            --next_difficulty;
        }
    }

    static const std::string sql = "INSERT INTO \"MiningReports\" (\"received\", \"preimage\", \"difficulty\", \"next_difficulty\", \"aggregate_work\") VALUES($1, $2, $3, $4, $5)";
    *tx << sql
        << absl::ToUnixNanos(state->received)
        << state->preimage
        << static_cast<int16_t>(state->current_difficulty)
        << static_cast<int16_t>(next_difficulty)
        << aggregate_work
        >> [=](const Result &r) {
            // FIXME: claim server funds?

            tx->setCommitCallback([=](bool){
                // Note that while each of the following statements are atomic,
                // the combined operation is not.  It is possible for reads to
                // interleave between these statements.
                ++(webcash::state().num_reports);
                webcash::state().difficulty.store(next_difficulty);
                webcash::state().num_unspent += state->webcash.size();

                if (webcash::state().logging) {
                    std::stringstream ss;
                    ss << "Got BLOCK!!! " << absl::BytesToHexString(absl::string_view((const char*)state->hash.begin(), 32))
                       << " aggregate_work=" << log2(aggregate_work)
                       << " difficulty=" << next_difficulty
                       << " reports=" << stats.num_reports
                       << " reports=" << stats.num_reports
                       << " reports=" << stats.num_reports
                       << " tx=" << stats.num_replace
                       << " unspent=" << stats.num_unspent
                       << std::endl;
                    std::cout << ss.str();
                }

                Json::Value ret(objectValue);
                ret["status"] = "success";
                ret["difficulty_target"] = next_difficulty;
                auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
                return callback(resp);
            });
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << sql << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

//  ----------------------
// | /api/v1/health_check |
//  ----------------------

struct HealthCheckState {
    // The health_check request as received from the caller.
    std::shared_ptr<Json::Value> msg;
    // The public webcash to check, deserialized.
    std::vector<PublicWebcash> args;
    // The generated SQL command to lookup unspent outputs and the results.
    std::string sql_unspent;
    std::map<uint256, Amount> unspent;
    // The generated SQL command to lookup spent hashes and the results.
    std::string sql_spent;
    std::set<uint256> spent;
};

void CheckUnspentOutputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<HealthCheckState> state,
    std::shared_ptr<DbClient> db); // Calls CheckSpentOutputs...

void CheckSpentOutputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<HealthCheckState> state,
    std::shared_ptr<DbClient> db); // Calls ReturnResults...

void ReturnResults(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<HealthCheckState> state,
    std::shared_ptr<DbClient> db); // Done

void V1::healthCheck(
    const HttpRequestPtr &req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    std::shared_ptr<HealthCheckState> state = std::make_shared<HealthCheckState>();

    state->msg = req->getJsonObject();
    if (!state->msg) {
        return callback(JSONRPCError("no JSON body"));
    }

    // Read input parameters as an array of webcash public string the user wants to check.
    if (!parse_public_webcashes(*state->msg, state->args)) {
        return callback(JSONRPCError("arguments needs to be array of webcash public webcash strings"));
    }

    auto db = drogon::app().getDbClient();
    if (!db) {
        return callback(JSONRPCError("error getting connection to database"));
    }

    std::vector<std::string> values;
    for (const auto& pk : state->args) {
        values.push_back(absl::StrCat("'\\x", absl::BytesToHexString(absl::string_view((char*)pk.pk.data(), 32)), "'::bytea"));
    }
    state->sql_unspent = absl::StrCat("SELECT \"hash\", \"amount\" FROM \"UnspentOutputs\" WHERE \"hash\" IN (", absl::StrJoin(values, ","), ")");
    state->sql_spent = absl::StrCat("SELECT \"hash\" FROM \"SpentHashes\" WHERE \"hash\" IN (", absl::StrJoin(values, ","), ")");

    CheckUnspentOutputs(callback, state, db);
}

void CheckUnspentOutputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<HealthCheckState> state,
    std::shared_ptr<DbClient> db
){
    *db << state->sql_unspent
        >> [=](const Result &result) {
            for (const auto& row : result) {
                if (row.size() != 2) {
                    std::cerr << "error: Expected two columns per row.  Got " << row.size() << "." << std::endl;
                    std::cerr << "error: Offending SQL: " << state->sql_unspent << std::endl;
                    return callback(JSONRPCError("sql error"));
                }
                if (row[0].length() != 32) {
                    std::cerr << "error: Expected 32-byte hash in first column.  Got " << row[0].length() << " bytes." << std::endl;
                    std::cerr << "error: Offending SQL: " << state->sql_unspent << std::endl;
                    return callback(JSONRPCError("sql error"));
                }
                std::string hash_bytes = row[0].as<std::string>();
                uint256 hash;
                std::copy((unsigned char*)hash_bytes.c_str(),
                          (unsigned char*)hash_bytes.c_str() + 32,
                          hash.data());
                state->unspent[hash] = Amount(row[1].as<uint64_t>());
            }
            return CheckSpentOutputs(callback, state, db);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << state->sql_unspent << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void CheckSpentOutputs(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<HealthCheckState> state,
    std::shared_ptr<DbClient> db
){
    *db << state->sql_spent
        >> [=](const Result &result) {
            for (const auto& row : result) {
                if (row.size() != 1) {
                    std::cerr << "error: Expected one columns per row.  Got " << row.size() << "." << std::endl;
                    std::cerr << "error: Offending SQL: " << state->sql_spent << std::endl;
                    return callback(JSONRPCError("sql error"));
                }
                if (row[0].length() != 32) {
                    std::cerr << "error: Expected 32-byte hash in first column.  Got " << row[0].length() << " bytes." << std::endl;
                    std::cerr << "error: Offending SQL: " << state->sql_spent << std::endl;
                    return callback(JSONRPCError("sql error"));
                }
                std::string hash_bytes = row[0].as<std::string>();
                uint256 hash;
                std::copy((unsigned char*)hash_bytes.c_str(),
                          (unsigned char*)hash_bytes.c_str() + 32,
                          hash.data());
                state->spent.insert(hash);
            }
            return ReturnResults(callback, state, db);
        }
        >> [=](const DrogonDbException &e) {
            std::cerr << "error: " << e.base().what() << std::endl;
            std::cerr << "error: Offending SQL: " << state->sql_spent << std::endl;
            return callback(JSONRPCError("sql error"));
        };
}

void ReturnResults(
    std::function<void (const HttpResponsePtr &)> callback,
    std::shared_ptr<HealthCheckState> state,
    std::shared_ptr<DbClient> db
){
    Json::Value results(objectValue);
    for (size_t i = 0; i < state->args.size(); ++i) {
        Json::Value status(objectValue);
        auto unspent = state->unspent.find(state->args[i].pk);
        if (unspent != state->unspent.end()) {
            status["spent"] = false;
            status["amount"] = to_string(unspent->second);
        } else if (state->spent.find(state->args[i].pk) != state->spent.end()) {
            status["spent"] = true;
        } else {
            // This is a bit obscure, but it matches the current server
            // behavior.  A never-seen webcash is indicated by a nullary
            // "spent" value.
            status["spent"] = Json::Value(nullValue);
        }
        // Use the original input as the key, so that the user is able
        // to find the record even if they sent a non-canonical encoding
        // (e.g. different hex capitalization).
        results[state->msg->get(i, to_string(state->args[i])).asString()] = status;
    }

    Json::Value ret(objectValue);
    ret["status"] = "success";
    ret["results"] = results;
    auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
    callback(resp);
}
} // namespace api

//  --------
// | /stats |
//  --------

void EconomyStats::asyncHandleHttpRequest(
    const HttpRequestPtr& req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    WebcashStats stats = webcash::state().getStats(absl::Now());

    Json::Value ret(objectValue);

    // Total circulation
    auto total = stats.total_circulation;
    uint64_t integer_part = absl::Uint128Low64(total / 100000000);
    uint64_t fractional_part = absl::Uint128Low64(total % 100000000);
    if (fractional_part == 0) {
        ret["circulation"] = integer_part;
    } else {
        ret["circulation"] = static_cast<double>(total) / 100000000.0;
    }
    std::stringstream ss;
    ss.imbue(std::locale(""));
    ss << std::fixed << integer_part;
    std::string s = to_string(Amount(fractional_part));
    ret["circulation_formatted"] = ss.str() + s.substr(1);
    ret["ratio"] = static_cast<double>(stats.total_circulation) / static_cast<double>(stats.expected_circulation);

    // Mining stats
    ret["mining_reports"] = stats.num_reports;
    ret["epoch"] = stats.epoch;
    ret["difficulty_target_bits"] = stats.difficulty;
    ret["mining_amount"] = to_string(stats.mining_amount);
    ret["mining_subsidy_amount"] = to_string(stats.subsidy_amount);

    auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
    resp->setExpiredTime(k_stats_cache_expiry);
    callback(resp);
}

// End of File
