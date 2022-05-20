// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "absl/flags/parse.h"
#include "absl/flags/usage.h"

#include "absl/strings/str_cat.h"

int main(int argc, char **argv)
{
    absl::SetProgramUsageMessage(absl::StrCat("Webcash server process.\n", argv[0]));
    absl::ParseCommandLine(argc, argv);

    return 0;
}

// End of File
