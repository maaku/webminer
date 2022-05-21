// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <functional>
#include <string>

#include "absl/flags/parse.h"
#include "absl/flags/usage.h"

#include "absl/strings/str_cat.h"

#include "boost/filesystem.hpp"

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpSimpleController.h>

using drogon::HttpSimpleController;
using drogon::HttpRequest;
using drogon::HttpRequestPtr;
using drogon::HttpResponse;
using drogon::HttpResponsePtr;
using drogon::Get;

class TermsOfService
    : public HttpSimpleController<TermsOfService>
{
protected:
    const ssize_t k_terms_cache_expiry = 2 * 60 * 60 /* 2 hours */;

public:
    virtual void asyncHandleHttpRequest(
            const HttpRequestPtr& req,
            std::function<void (const HttpResponsePtr &)> &&callback
        ) override;

    PATH_LIST_BEGIN
    PATH_ADD("/terms", Get);
    PATH_ADD("/terms/text", Get);
    PATH_LIST_END
};

void TermsOfService::asyncHandleHttpRequest(
    const HttpRequestPtr& req,
    std::function<void (const HttpResponsePtr &)> &&callback
){
    auto resp = HttpResponse::newHttpResponse();
    std::string filename;
    if (req && req->getPath() == "/terms") {
        filename = "terms/terms.html";
        resp->setContentTypeCode(drogon::CT_TEXT_HTML);
    }
    else if (req && req->getPath() == "/terms/text") {
        filename = "terms/terms.text";
        resp->setContentTypeCode(drogon::CT_TEXT_PLAIN);
    } else {
        // If we get here, our view controller is messed up.
        // Check the path definitions.
        callback(HttpResponse::newNotFoundResponse());
        return;
    }
    assert(!filename.empty());
    std::ifstream file(filename);
    std::stringstream buffer;
    buffer << file.rdbuf();
    resp->setBody(buffer.str());
    resp->setExpiredTime(k_terms_cache_expiry);
    callback(resp);
}

int main(int argc, char **argv)
{
    absl::SetProgramUsageMessage(absl::StrCat("Webcash server process.\n", argv[0]));
    absl::ParseCommandLine(argc, argv);

    // Set HTTP listener address and port
    drogon::app().addListener("127.0.0.1", 8000);

    // Load config file, if present
    if (boost::filesystem::exists("webcashd.conf")) {
        drogon::app().loadConfigFile("webcashd.conf");
    }

    // Run HTTP server
    drogon::app().run();

    return 0;
}

// End of File
