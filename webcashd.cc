// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <stdint.h>

#include <atomic>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "absl/flags/parse.h"
#include "absl/flags/usage.h"

#include "absl/numeric/int128.h"

#include "absl/strings/str_cat.h"

#include "absl/time/clock.h"
#include "absl/time/time.h"

#include "boost/filesystem.hpp"

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpController.h>
#include <drogon/HttpSimpleController.h>

#include <json/json.h>

#include "async.h"
#include "crypto/sha256.h"
#include "uint256.h"
#include "sync.h"
#include "webcash.h"

using std::to_string;

using drogon::HttpController;
using drogon::HttpSimpleController;
using drogon::HttpRequest;
using drogon::HttpRequestPtr;
using drogon::HttpResponse;
using drogon::HttpResponsePtr;
using drogon::Get;
using drogon::Post;

using Json::ValueType::objectValue;

struct MiningReport {
    std::string preimage; // source: client
    absl::uint128 aggregate_work; // cached
    absl::Time received; // source: server
    uint8_t difficulty; // cached
};

struct Replacement {
    std::map<uint256, Amount> inputs;
    std::map<uint256, Amount> outputs;
    absl::Time received;
};

struct WebcashStats {
    absl::Time timestamp;
    absl::uint128 total_circulation = 0;
    absl::uint128 expected_circulation = 0;
    unsigned num_reports;
    Amount mining_amount;
    Amount subsidy_amount;
    unsigned epoch = 0;
    unsigned difficulty = 0;
};

class WebcashEconomy {
public:
    mutable Mutex cs;
public: // should be protected:
    const int64_t INITIAL_MINING_AMOUNT = 20000000000000LL;
    const int64_t INITIAL_SUBSIDY_AMOUNT = 1000000000000LL;
    std::atomic<unsigned> difficulty = 28; // cached
    std::atomic<size_t> num_reports = 0; // cached

    absl::Time genesis = absl::Now(); // treated as constant
    std::map<uint256, Amount> unspent GUARDED_BY(cs);
    std::set<uint256> spent GUARDED_BY(cs);
    std::vector<MiningReport> mining_reports GUARDED_BY(cs);
    std::map<uint256, size_t> proof_of_works GUARDED_BY(cs);
    std::vector<Replacement> audit_log GUARDED_BY(cs);

public:
    WebcashEconomy() = default;
    // Non-copyable:
    WebcashEconomy(const WebcashEconomy&) = delete;
    WebcashEconomy& operator=(const WebcashEconomy&) = delete;

    inline unsigned getDifficulty() const {
        return difficulty.load();
    }

    unsigned getEpoch() const {
        return num_reports.load() / 525000;
    }

    inline Amount getMiningAmount() const {
        size_t epoch = num_reports.load() / 525000;
        return (epoch > 63)
            ? Amount{0}
            : Amount{INITIAL_MINING_AMOUNT >> epoch};
    }

    inline Amount getSubsidyAmount() const {
        size_t epoch = num_reports.load() / 525000;
        return (epoch > 63)
            ? Amount{0}
            : Amount{INITIAL_SUBSIDY_AMOUNT >> epoch};
    }

    WebcashStats getStats(absl::Time now);
};

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

WebcashEconomy& state()
{
    static WebcashEconomy economy;
    return economy;
}

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

bool parse_secrets(
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

class TermsOfService
    : public HttpSimpleController<TermsOfService>
{
protected:
    const ssize_t k_terms_cache_expiry = 2 * 60 * 60 /* 2 hours */;

public:
    PATH_LIST_BEGIN
        PATH_ADD("/terms", Get);
        PATH_ADD("/terms/text", Get);
    PATH_LIST_END

    virtual void asyncHandleHttpRequest(
            const HttpRequestPtr& req,
            std::function<void (const HttpResponsePtr &)> &&callback
        ) override;
};

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
class V1
    : public HttpController<V1>
{
public:
    METHOD_LIST_BEGIN
        METHOD_ADD(V1::replace, "/replace", Post);
        METHOD_ADD(V1::target, "/target", Get);
        METHOD_ADD(V1::miningReport, "/mining_report", Post);
        METHOD_ADD(V1::healthCheck, "/health_check", Post);
    METHOD_LIST_END

    void replace(
        const HttpRequestPtr &req,
        std::function<void (const HttpResponsePtr &)> &&callback);

    void target(
        const HttpRequestPtr &req,
        std::function<void (const HttpResponsePtr &)> &&callback);

    void miningReport(
        const HttpRequestPtr &req,
        std::function<void (const HttpResponsePtr &)> &&callback);

    void healthCheck(
        const HttpRequestPtr &req,
        std::function<void (const HttpResponsePtr &)> &&callback);
};

void V1::replace(
    const HttpRequestPtr &req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    Json::Value ret(__func__);
    auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
    callback(resp);
}

void V1::target(
    const HttpRequestPtr &req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    Json::Value ret(__func__);
    auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
    callback(resp);
}

void V1::miningReport(
    const HttpRequestPtr &req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    Json::Value ret(__func__);
    auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
    callback(resp);
}

void V1::healthCheck(
    const HttpRequestPtr &req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    Json::Value ret(__func__);
    auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
    callback(resp);
}
} // namespace api

class EconomyStats
    : public HttpSimpleController<EconomyStats>
{
protected:
    const ssize_t k_stats_cache_expiry = 10 /* 10 seconds */;

public:
    PATH_LIST_BEGIN
        PATH_ADD("/stats", Get);
    PATH_LIST_END

    virtual void asyncHandleHttpRequest(
            const HttpRequestPtr& req,
            std::function<void (const HttpResponsePtr &)> &&callback
        ) override;
};

void EconomyStats::asyncHandleHttpRequest(
    const HttpRequestPtr& req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    WebcashStats stats;
    {
        auto& state = ::state();
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

int main(int argc, char **argv)
{
    absl::SetProgramUsageMessage(absl::StrCat("Webcash server process.\n", argv[0]));
    absl::ParseCommandLine(argc, argv);
    auto& app = drogon::app();

    const std::string algo = SHA256AutoDetect();
    std::cout << "Using SHA256 algorithm '" << algo << "'." << std::endl;

    // Configure the number of worker threads
    drogon::app().setThreadNum(get_num_workers());

    // Set HTTP listener address and port
    app.addListener("127.0.0.1", 8000);

    // Load config file, if present
    if (boost::filesystem::exists("webcashd.conf")) {
        app.loadConfigFile("webcashd.conf");
    }

    // Run HTTP server
    app.run();

    return 0;
}

// End of File
