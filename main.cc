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

#include "absl/time/clock.h"
#include "absl/time/time.h"

#include <cpr/cpr.h>

#include <univalue.h>

struct ProtocolSettings {
    // The amount the miner is allowed to claim.
    int64_t mining_amount;
    // The amount which is surrendered to the server operator.
    int64_t subsidy_amount;
    // The ratio of initial issuance distributed to expected amount.
    float ratio;
    // The number of leading bits which must be zero for a work candidate to be
    // accepted by the server.
    int difficulty;
};

bool get_protocol_settings(ProtocolSettings& settings)
{
    cpr::Response r = cpr::Get(cpr::Url{"https://webcash.tech/api/v1/target"});
    if (r.status_code != 200) {
        std::cerr << "Error: returned invalid response to ProtocolSettings request: status_code=" << r.status_code << ", text='" << r.text << "'" << std::endl;
        return false;
    }
    UniValue o;
    o.read(r.text);
    const UniValue& difficulty = o["difficulty_target_bits"];
    if (!difficulty.isNum()) {
        std::cerr << "Error: expected integer for 'difficulty' field of ProtocolSettings response, got '" << difficulty.write() << "' instead." << std::endl;
        return false;
    }
    const UniValue& ratio = o["ratio"];
    if (!ratio.isNum()) {
        std::cerr << "Error: expected real number for 'ratio' field of ProtocolSettings response, got '" << ratio.write() << "' instead." << std::endl;
        return false;
    }
    const UniValue& mining_amount = o["mining_amount"];
    if (!mining_amount.isNum()) {
        std::cerr << "Error: expected integer for 'mining_amount' field of ProtocolSettings response, got '" << mining_amount.write() << "' instead." << std::endl;
        return false;
    }
    const UniValue& subsidy_amount = o["mining_subsidy_amount"];
    if (!subsidy_amount.isNum()) {
        std::cerr << "Error: expected integer for 'subsidy_amount' field of ProtocolSettings response, got '" << subsidy_amount.write() << "' instead." << std::endl;
        return false;
    }
    settings.difficulty = difficulty.get_int();
    settings.ratio = ratio.get_real();
    settings.mining_amount = mining_amount.get_int64();
    settings.subsidy_amount = subsidy_amount.get_int64();
    return true;
}

std::string get_speed_string(int64_t attempts, absl::Time begin, absl::Time end) {
    float speed = attempts / absl::ToDoubleSeconds(end - begin);
    if (speed < 2e3f)
        return std::to_string(speed) + " hps";
    if (speed < 2e6f)
        return std::to_string(speed / 1e3f) + " khps";
    if (speed < 2e9f)
        return std::to_string(speed / 1e6f) + " Mhps";
    if (speed < 2e12f)
        return std::to_string(speed / 1e9f) + " Ghps";
    return std::to_string(speed / 1e12f) + " Thps";
}

int main(int argc, char **argv)
{
    absl::SetProgramUsageMessage(absl::StrCat("Webcash mining daemon.\n", argv[0]));
    absl::ParseCommandLine(argc, argv);

    ProtocolSettings settings;
    if (!get_protocol_settings(settings)) {
        std::cerr << "Error: could not fetch protocol settings from server; exiting" << std::endl;
        return 1;
    }
    std::cout << "server says"
              << " difficulty=" << settings.difficulty
              << " ratio=" << settings.ratio
              << std::endl;
    absl::Time current_time = absl::Now();
    absl::Time last_settings_fetch = current_time;
    absl::Time next_settings_fetch = current_time + absl::Seconds(5);

    bool done = false;
    int64_t attempts = 0;
    while (!done) {
        current_time = absl::Now();
        if (current_time >= next_settings_fetch) {
            // Fetch updated protocol settings, and report changes + current
            // hash speed to the user.
            if (get_protocol_settings(settings)) {
                std::cout << "server says"
                          << " difficulty=" << settings.difficulty
                          << " ratio=" << settings.ratio
                          << " speed=" << get_speed_string(attempts, last_settings_fetch, current_time)
                          << std::endl;
            }
            // Schedule the next settings fetch
            last_settings_fetch = current_time;
            next_settings_fetch = current_time + absl::Seconds(5);
            // Reset hash counter
            attempts = 0;
        }

        ++attempts;
    }

    return 0;
}

// End of File
