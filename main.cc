// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iostream>

#include <string>
#include <vector>

#include "absl/flags/parse.h"
#include "absl/flags/usage.h"

#include "absl/strings/str_cat.h"

#include <cpr/cpr.h>

int main(int argc, char **argv)
{
    absl::SetProgramUsageMessage(absl::StrCat("Webcash mining daemon.\n", argv[0]));

    absl::ParseCommandLine(argc, argv);

    cpr::Response r = cpr::Get(cpr::Url{"https://webcash.tech/api/v1/target"});
    std::cout << r.status_code << std::endl;
    std::cout << r.text << std::endl;

    return 0;
}

// End of File
