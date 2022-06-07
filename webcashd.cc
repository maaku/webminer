// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "absl/flags/parse.h"
#include "absl/flags/usage.h"

#include "absl/strings/str_cat.h"

#include "boost/filesystem.hpp"

#include <drogon/HttpAppFramework.h>

#include "async.h"
#include "crypto/sha256.h"
#include "server.h"

int main(int argc, char **argv)
{
    absl::SetProgramUsageMessage(absl::StrCat("Webcash server process.\n", argv[0]));
    absl::ParseCommandLine(argc, argv);
    auto& app = drogon::app();

    const std::string algo = SHA256AutoDetect();
    std::cout << "Using SHA256 algorithm '" << algo << "'." << std::endl;

    // Configure the number of worker threads
    int num_workers = get_num_workers();
    app.setThreadNum(num_workers);

    // Create the database connection
    app.createDbClient(
        "postgresql", // dbType
        "localhost", // host
        5432,        // port
        "postgres",  // databaseName
        "postgres",  // username
        "mysecretpassword", // password
        num_workers, // connectionNum
        "webcashd",  // filename
        "default",   // name
        false,       // isFast
        "utf8",      // characterSet
        10.0         // timeout
    );

    // Create/upgrade the database tables
    webcash::upgradeDb();

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
