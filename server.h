// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#ifndef SERVER_H
#define SERVER_H

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

    inline unsigned getEpoch() const {
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

namespace webcash {
    WebcashEconomy& state();
} // webcash

std::shared_ptr<drogon::HttpResponse> JSONRPCError(const std::string& err);
bool check_legalese(const Json::Value& request);
bool parse_secret_webcashes(const Json::Value& array, std::map<uint256, SecretWebcash>& webcash);
bool parse_public_webcashes(const Json::Value& array, std::vector<PublicWebcash>& webcash);

class TermsOfService
    : public drogon::HttpSimpleController<TermsOfService>
{
protected:
    const ssize_t k_terms_cache_expiry = 2 * 60 * 60 /* 2 hours */;

public:
    PATH_LIST_BEGIN
        PATH_ADD("/terms", drogon::Get);
        PATH_ADD("/terms/text", drogon::Get);
    PATH_LIST_END

    virtual void asyncHandleHttpRequest(
            const drogon::HttpRequestPtr& req,
            std::function<void (const drogon::HttpResponsePtr &)> &&callback
        ) override;
};

namespace api {
class V1
    : public drogon::HttpController<V1>
{
protected:
    const ssize_t k_target_cache_expiry = 2 * 60 * 60 /* 2 hours */;

public:
    METHOD_LIST_BEGIN
        METHOD_ADD(V1::replace, "/replace", drogon::Post);
        METHOD_ADD(V1::target, "/target", drogon::Get);
        METHOD_ADD(V1::miningReport, "/mining_report", drogon::Post);
        METHOD_ADD(V1::healthCheck, "/health_check", drogon::Post);
    METHOD_LIST_END

    void replace(
        const drogon::HttpRequestPtr &req,
        std::function<void (const drogon::HttpResponsePtr &)> &&callback);

    void target(
        const drogon::HttpRequestPtr &req,
        std::function<void (const drogon::HttpResponsePtr &)> &&callback);

    void miningReport(
        const drogon::HttpRequestPtr &req,
        std::function<void (const drogon::HttpResponsePtr &)> &&callback);

    void healthCheck(
        const drogon::HttpRequestPtr &req,
        std::function<void (const drogon::HttpResponsePtr &)> &&callback);
};
} // namespace api

class EconomyStats
    : public drogon::HttpSimpleController<EconomyStats>
{
protected:
    const ssize_t k_stats_cache_expiry = 10 /* 10 seconds */;

public:
    PATH_LIST_BEGIN
        PATH_ADD("/stats", drogon::Get);
    PATH_LIST_END

    virtual void asyncHandleHttpRequest(
            const drogon::HttpRequestPtr& req,
            std::function<void (const drogon::HttpResponsePtr &)> &&callback
        ) override;
};

#endif // SERVER_H

// End of File
