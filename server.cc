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
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "absl/numeric/int128.h"

#include "absl/time/clock.h"
#include "absl/time/time.h"

#include <drogon/HttpController.h>
#include <drogon/HttpSimpleController.h>

#include <json/json.h>

#include "sync.h"
#include "uint256.h"
#include "webcash.h"

using std::to_string;

using drogon::HttpController;
using drogon::HttpSimpleController;
using drogon::HttpRequest;
using drogon::HttpRequestPtr;
using drogon::HttpResponse;
using drogon::HttpResponsePtr;

using Json::ValueType::nullValue;
using Json::ValueType::objectValue;

WebcashStats WebcashEconomy::getStats(absl::Time now)
{
    WebcashStats stats;
    stats.timestamp = now;
    do {
        stats.num_reports = num_reports.load();
        stats.difficulty = difficulty.load();
    } while (stats.num_reports != num_reports.load());

    stats.total_circulation = 0;
    size_t count = stats.num_reports;
    uint64_t value = INITIAL_MINING_AMOUNT;
    while (525000 < count) {
        stats.total_circulation += value * 525000;
        count -= 525000;
    }
    stats.total_circulation += count * value;

    stats.expected_circulation = 0;
    count = static_cast<size_t>((stats.timestamp - genesis) / absl::Seconds(10));
    value = INITIAL_MINING_AMOUNT;
    while (525000 < count) {
        stats.expected_circulation += value * 525000;
        count -= 525000;
    }
    stats.expected_circulation += count * value;

    // Do not use the class methods because that would re-fetch num_reports,
    // which might have been updated.
    stats.epoch = stats.num_reports / 525000;
    if (stats.epoch > 63) {
        stats.mining_amount = 0;
        stats.subsidy_amount = 0;
    } else {
        stats.mining_amount = INITIAL_MINING_AMOUNT >> stats.epoch;
        stats.subsidy_amount = INITIAL_SUBSIDY_AMOUNT >> stats.epoch;
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

std::shared_ptr<drogon::HttpResponse> JSONRPCError(const std::string& err)
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
    for (int i = 0; i < array.size(); ++i) {
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
    for (int i = 0; i < array.size(); ++i) {
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
void V1::replace(
    const HttpRequestPtr &req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    absl::Time received = absl::Now();

    auto maybe_msg = req->getJsonObject();
    if (!maybe_msg || !maybe_msg->isObject()) {
        return callback(JSONRPCError("no JSON body"));
    }
    auto msg = *maybe_msg;
    if (!check_legalese(msg)) {
        return callback(JSONRPCError("didn't accept terms"));
    }

    // Extract 'inputs'
    if (!msg.isMember("webcashes")) {
        return callback(JSONRPCError("no inputs"));
    }
    std::map<uint256, SecretWebcash> inputs;
    if (!parse_secret_webcashes(msg["webcashes"], inputs)) {
        return callback(JSONRPCError("can't parse inputs"));
    }
    Amount total_in(0);
    for (const auto& item : inputs) {
        const auto& wc = item.second;
        total_in += wc.amount;
        if (total_in < 1 || wc.amount < 1) {
            return callback(JSONRPCError("overflow"));
        }
    }

    // Extract 'outputs'
    if (!msg.isMember("new_webcashes")) {
        return callback(JSONRPCError("no outputs"));
    }
    std::map<uint256, SecretWebcash> outputs;
    if (!parse_secret_webcashes(msg["new_webcashes"], outputs)) {
        return callback(JSONRPCError("can't parse inputs"));
    }
    Amount total_out(0);
    for (const auto& item : outputs) {
        const auto& wc = item.second;
        total_out += wc.amount;
        if (total_out < 1 || wc.amount < 1) {
            return callback(JSONRPCError("overflow"));
        }
    }

    // Check inputs == outputs
    if (total_in != total_out) {
        return callback(JSONRPCError("inbalance"));
    }

    // Now we perform checks that require access to global state.
    {
        // Lock the global state
        auto& state = webcash::state();
        LOCK(state.cs);

        // Check that inputs exist with claimed value
        for (const auto& item : inputs) {
            auto iter = state.unspent.find(item.first);
            if (iter == state.unspent.end()) {
                return callback(JSONRPCError("missing"));
            }
            if (iter->second != item.second.amount) {
                return callback(JSONRPCError("wrong amount"));
            }
        }

        // Check that outputs do not exist
        for (const auto& item : outputs) {
            if (state.unspent.find(item.first) != state.unspent.end()) {
                return callback(JSONRPCError("reuse"));
            }
        }

        // Keep a record of changes for the audit log
        Replacement tx;
        tx.received = received;

        // Remove inputs
        for (const auto& item : inputs) {
            state.unspent.erase(item.first);
            state.spent.insert(item.first);
            tx.inputs[item.first] = item.second.amount;
        }

        // Add outputs
        for (const auto& item : outputs) {
            state.unspent[item.first] = item.second.amount;
            tx.outputs[item.first] = item.second.amount;
        }

        // Record to audit log
        state.audit_log.push_back(std::move(tx));

        std::cerr << "Replaced " << inputs.size()
                  << " input for " << outputs.size()
                  << " output (total: ₩" << to_string(total_in) << ")."
                  << " tx=" << state.audit_log.size()
                  << " utxos=" << state.unspent.size()
                  << std::endl;
    }

    Json::Value ret(objectValue);
    ret["status"] = "success";
    auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
    callback(resp);
}

void V1::target(
    const HttpRequestPtr &req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    WebcashStats stats;
    {
        auto& state = webcash::state();
        LOCK(state.cs);
        stats = state.getStats(absl::Now());
    }

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

void V1::miningReport(
    const HttpRequestPtr &req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    absl::Time received = absl::Now();

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
    auto preimage_b64 = msg["preimage"].asString();
    std::string preimage_str;
    if (!absl::Base64Unescape(preimage_b64, &preimage_str)) {
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
    std::map<uint256, SecretWebcash> webcash;
    if (!parse_secret_webcashes(preimage["webcash"], webcash)) {
        return callback(JSONRPCError("'webcash' field in preimage needs to be array of webcash secrets"));
    }

    // Read 'subsidy', the array of webcash claim codes given to the server
    if (!preimage.isMember("subsidy")) {
        return callback(JSONRPCError("missing 'subsidy' field in peimage"));
    }
    std::map<uint256, SecretWebcash> subsidy;
    if (!parse_secret_webcashes(preimage["subsidy"], subsidy)) {
        return callback(JSONRPCError("'subsidy' field in preimage needs to be array of webcash secrets"));
    }

    // Read 'timestamp'
    bool has_timestamp = false;
    absl::Time timestamp = absl::UnixEpoch();
    if (preimage.isMember("timestamp")) {
        if (!preimage["timestamp"].isConvertibleTo(Json::realValue)) {
            return callback(JSONRPCError("'timestamp' field in preimage must be numeric"));
        }
        timestamp = absl::FromUnixSeconds(static_cast<int64_t>(preimage["timestamp"].asDouble()));
        has_timestamp = true;
    }

    // Read 'difficulty'
    bool has_difficulty = false;
    unsigned difficulty = 0;
    if (preimage.isMember("difficulty")) {
        if (!preimage["difficulty"].isConvertibleTo(Json::uintValue)) {
            return callback(JSONRPCError("'difficulty' field in preimage must be small positive integer"));
        }
        difficulty = preimage["difficulty"].asUInt();
        if (difficulty > 255) {
            return callback(JSONRPCError("'difficulty' field in preimage is too high"));
        }
        has_difficulty = true;
    }

    // Check 'webcash'
    Amount mining_amount(0);
    for (const auto& item : webcash) {
        mining_amount += item.second.amount;
        if (mining_amount < 1 || item.second.amount < 1) {
            return callback(JSONRPCError("overflow"));
        }
    }

    // Check 'subsidy'
    Amount subsidy_amount(0);
    for (const auto& item : subsidy) {
        subsidy_amount += item.second.amount;
        if (subsidy_amount < 1 || item.second.amount < 1) {
            return callback(JSONRPCError("overflow"));
        }
        auto itr = webcash.find(item.first);
        if (itr == webcash.end()) {
            return callback(JSONRPCError("missing subsidy from webcash"));
        }
        if (itr->second.amount != item.second.amount) {
            return callback(JSONRPCError("subsidy doesn't match webcash"));
        }
    }
    if (webcash.size() < subsidy.size() || mining_amount < subsidy_amount) {
        return callback(JSONRPCError("internal server error")); // should have failed above
    }

    // Check 'timestamp', if present
    if (has_timestamp) {
        absl::Time min_time = received - absl::Hours(2);
        absl::Time max_time = received + absl::Hours(2);
        if (timestamp < min_time || max_time < timestamp) {
            return callback(JSONRPCError("timestamp of mining report must be within 2 hours of receipt by server"));
        }
    }

    // Calculate proof-of-work
    uint256 hash;
    CSHA256().Write((unsigned char*)preimage_b64.c_str(), preimage_b64.length()).Finalize(hash.data());
    unsigned bits = get_apparent_difficulty(hash);
    if (bits < 25) { // DoS prevention
        return callback(JSONRPCError("difficulty too low"));
    }

    // Check 'difficulty', if present
    if (has_difficulty) {
        if (bits < difficulty) {
            return callback(JSONRPCError("proof-of-work doesn't match committed difficulty"));
        }
    }

    // Now we perform checks that require access to global state.
    unsigned next_difficulty = 0;
    {
        // Lock the global state
        auto& state = webcash::state();
        LOCK(state.cs);

        // Difficulty can change with the mere passage of time, so we record the
        // current difficulty as soon as we have locked the state mutex.
        unsigned current_difficulty = state.difficulty.load();

        // Check committed difficulty meets current difficulty
        if (has_difficulty && difficulty < current_difficulty) {
            return callback(JSONRPCError("committed difficulty is less than current difficulty"));
        }

        // Check proof-of-work meets difficulty
        if (bits < current_difficulty) {
            // Not necessarily an error--perhaps the difficulty changed?
            return callback(JSONRPCError("proof of work doesn't meet current difficulty"));
        }

        // Check proof-of-work hasn't been used yet
        if (state.proof_of_works.find(hash) != state.proof_of_works.end()) {
            return callback(JSONRPCError("reused preimage"));
        }

        // Check outputs do not exist
        for (const auto& item : webcash) {
            if (state.unspent.find(item.first) != state.unspent.end()) {
                return callback(JSONRPCError("output already exists"));
            }
        }

        // Check outputs sum to expected value
        if (mining_amount != state.getMiningAmount()) {
            return callback(JSONRPCError("outputs don't match allowed amount"));
        }

        // Check subsidy sums to expected value
        if (subsidy_amount != state.getSubsidyAmount()) {
            return callback(JSONRPCError("subsidy doesn't match required amount"));
        }

        // Create outputs
        for (const auto& item : webcash) {
            state.unspent[item.first] = item.second.amount;
        }

        // Store mining report
        MiningReport report;
        report.preimage = preimage_b64;
        absl::uint128 work = 1;
        work <<= current_difficulty;
        report.aggregate_work = (state.mining_reports.empty() ? 0 : state.mining_reports.back().aggregate_work) + work;
        report.received = received;
        report.difficulty = current_difficulty;
        state.proof_of_works[hash] = state.mining_reports.size();
        state.mining_reports.push_back(std::move(report));
        ++state.num_reports;

        next_difficulty = current_difficulty;
        if ((state.mining_reports.size() & 0x7f) == 0) { // mod 128
            WebcashStats stats = state.getStats(received);
            int look_back_window = 128; // about 10 to 15 minutes
            if (state.mining_reports.size() == look_back_window) {
                --look_back_window;
            }
            absl::Duration expected = look_back_window * absl::Seconds(10);
            absl::Duration actual = received - (state.mining_reports.rbegin() + look_back_window)->received;
            if (actual <= expected && stats.expected_circulation <= stats.total_circulation) {
                // We're early and we're ahead of the issuance curve
                ++next_difficulty;
            }
            if (expected <= actual && stats.total_circulation <= stats.expected_circulation) {
                // We're late and we're behind the issuance curve
                --next_difficulty;
            }
        }
        state.difficulty.store(next_difficulty);

        // FIXME: claim server funds?

        std::cout << "Got BLOCK!!! "
                  << absl::BytesToHexString(absl::string_view((const char*)hash.begin(), 32))
                  << " aggregate_work=" << log2(static_cast<double>(state.mining_reports.back().aggregate_work))
                  << " difficulty=" << next_difficulty
                  << " num_reports=" << state.mining_reports.size()
                  << " outputs=" << state.unspent.size()
                  << std::endl;
    }

    Json::Value ret(objectValue);
    ret["status"] = "success";
    ret["difficulty_target"] = next_difficulty;
    auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
    callback(resp);
}

void V1::healthCheck(
    const HttpRequestPtr &req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    auto maybe_msg = req->getJsonObject();
    if (!maybe_msg) {
        return callback(JSONRPCError("no JSON body"));
    }
    auto msg = *maybe_msg;

    // Read input parameters as an array of webcash public string the user wants to check.
    std::vector<PublicWebcash> input;
    if (!parse_public_webcashes(msg, input)) {
        return callback(JSONRPCError("arguments needs to be array of webcash public webcash strings"));
    }

    Json::Value results(objectValue);
    for (size_t i = 0; i < input.size();) {
        // Obtain database lock.
        auto& state = webcash::state();
        LOCK(state.cs);

        // Handle up to 20 inputs before releasing the lock to prevent contention.
        size_t end = std::min(i + 20, input.size());
        for (; i < end; ++i) {
            Json::Value status(objectValue);
            auto unspent = state.unspent.find(input[i].pk);
            if (unspent != state.unspent.end()) {
                status["spent"] = false;
                status["amount"] = to_string(unspent->second);
            } else if (state.spent.find(input[i].pk) != state.spent.end()) {
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
            results[msg.get(i, to_string(input[i])).asString()] = status;
        }
    }

    Json::Value ret(objectValue);
    ret["status"] = "success";
    ret["results"] = results;
    auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
    callback(resp);
}
} // namespace api

void EconomyStats::asyncHandleHttpRequest(
    const HttpRequestPtr& req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    WebcashStats stats;
    {
        auto& state = webcash::state();
        LOCK(state.cs);
        stats = state.getStats(absl::Now());
    }

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
