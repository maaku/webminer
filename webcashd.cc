// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "absl/flags/parse.h"
#include "absl/flags/usage.h"

#include "absl/strings/str_cat.h"

#include <drogon/HttpAppFramework.h>

int main(int argc, char **argv)
{
    absl::SetProgramUsageMessage(absl::StrCat("Webcash server process.\n", argv[0]));
    absl::ParseCommandLine(argc, argv);

    // Set HTTP listener address and port
    drogon::app().addListener("127.0.0.1", 8000);

    // Load config file
    drogon::app().loadConfigFile("webcashd.conf");

    // Run HTTP server
    drogon::app().run();

    return 0;
}

// End of File
