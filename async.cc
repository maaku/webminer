// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iostream>

#include <thread>

#include "absl/flags/flag.h"

ABSL_FLAG(unsigned, workers, 0, "number of mining threads to spawn");

int get_num_workers()
{
    int num_workers = absl::GetFlag(FLAGS_workers);
    if (num_workers > 1024) {
        std::cerr << "Error: --workers cannot be larger than 1024" << std::endl;
        return 1;
    }
    if (num_workers == 0) {
        num_workers = std::thread::hardware_concurrency();
        if (num_workers != 0) {
            std::cout << "Auto-detected the hardware concurrency to be " << num_workers << std::endl;
        } else {
            std::cout << "Could not auto-detect the hardware concurrency; assuming a value of 1" << std::endl;
            num_workers = 1;
        }
    }
    return num_workers;
}

// End of File
