// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <functional>
#include <string>
#include <utility>

#include "absl/flags/parse.h"
#include "absl/flags/usage.h"

#include "absl/strings/str_cat.h"

#include "boost/filesystem.hpp"

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpController.h>
#include <drogon/HttpSimpleController.h>

#include <json/json.h>

#include "async.h"
#include "crypto/sha256.h"

using drogon::HttpController;
using drogon::HttpSimpleController;
using drogon::HttpRequest;
using drogon::HttpRequestPtr;
using drogon::HttpResponse;
using drogon::HttpResponsePtr;
using drogon::Get;
using drogon::Post;

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

class EconomyStatus
    : public HttpSimpleController<EconomyStatus>
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

void EconomyStatus::asyncHandleHttpRequest(
    const HttpRequestPtr& req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    Json::Value ret;
    auto resp = HttpResponse::newHttpJsonResponse(std::move(ret));
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
