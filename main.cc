// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iostream>

#include <string>
#include <vector>

#include <atomic>
#include <mutex>
#include <thread>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

#include "absl/time/clock.h"
#include "absl/time/time.h"

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <openssl/bn.h>

#include <univalue.h>

#include "crypto/sha256.h"
#include "random.h"
#include "uint256.h"

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
    httplib::Client cli("https://webcash.tech");
    cli.set_read_timeout(60, 0); // 60 seconds
    cli.set_write_timeout(60, 0); // 60 seconds
    auto r = cli.Get("/api/v1/target");
    if (!r) {
        std::cerr << "Error: returned invalid response to ProtocolSettings request: " << r.error() << std::endl;
        return false;
    }
    if (r->status != 200) {
        std::cerr << "Error: returned invalid response to ProtocolSettings request: status_code=" << r->status << ", text='" << r->body << "'" << std::endl;
        return false;
    }
    UniValue o;
    o.read(r->body);
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

struct SecretWebcash {
    uint256 sk;
    int64_t amount;
};

static std::string webcash_string(int64_t amount, const absl::string_view& type, const uint256& hash)
{
    if (amount < 0) {
        amount = 0;
    }
    return absl::StrCat("e", std::to_string(amount), ":", type, ":", absl::BytesToHexString(absl::string_view((const char*)hash.data(), hash.size())));
}

std::string to_string(const SecretWebcash& esk)
{
    return webcash_string(esk.amount, "secret", esk.sk);
}

struct PublicWebcash {
    uint256 pk;
    int64_t amount;

    PublicWebcash(const SecretWebcash& esk)
        : amount(esk.amount)
    {
        CSHA256()
            .Write(esk.sk.data(), esk.sk.size())
            .Finalize(pk.data());
    }
};

std::string to_string(const PublicWebcash& epk)
{
    return webcash_string(epk.amount, "public", epk.pk);
}

bool check_proof_of_work(const uint256& hash, int difficulty)
{
    const unsigned char* ptr = hash.begin();
    while (difficulty >= 8) {
        if (*ptr != 0) {
            return false;
        }
        ++ptr;
        difficulty -= 8;
    }
    switch (difficulty) {
        case 1: return (*ptr <= 0x7f);
        case 2: return (*ptr <= 0x3f);
        case 3: return (*ptr <= 0x1f);
        case 4: return (*ptr <= 0x0f);
        case 5: return (*ptr <= 0x07);
        case 6: return (*ptr <= 0x03);
        case 7: return (*ptr <= 0x01);
    }
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

std::condition_variable g_update_thread_cv;
std::atomic<bool> g_shutdown{false};

std::mutex g_state_mutex;
std::atomic<int> g_difficulty{16};
std::atomic<int64_t> g_mining_amount{20000};
std::atomic<int64_t> g_subsidy_amount{1000};
std::atomic<int64_t> g_attempts{0};
absl::Time g_last_rng_update{absl::UnixEpoch()};
absl::Time g_next_rng_update{absl::UnixEpoch()};
absl::Time g_last_settings_fetch{absl::UnixEpoch()};
absl::Time g_next_settings_fetch{absl::UnixEpoch()};

void update_thread_func()
{
    bool update_rng = true;
    bool fetch_settings = true;

    while (!g_shutdown) {
        absl::Time current_time = absl::Now();

        if (update_rng) {
            update_rng = false;
            // Gather entropy for RNG
            RandAddPeriodic();
            // Schedule next update
            current_time = absl::Now();
            g_last_rng_update = current_time;
            g_next_rng_update = current_time + absl::Minutes(30);
        }

        if (fetch_settings) {
            fetch_settings = false;
            // Fetch updated protocol settings, and report changes + current
            // hash speed to the user.
            int64_t attempts = g_attempts.exchange(0);
            ProtocolSettings settings;
            if (get_protocol_settings(settings)) {
                std::cout << "server says"
                          << " difficulty=" << settings.difficulty
                          << " ratio=" << settings.ratio
                          << " speed=" << get_speed_string(attempts, g_last_settings_fetch, current_time)
                          << std::endl;
                g_difficulty = settings.difficulty;
                g_mining_amount = settings.mining_amount;
                g_subsidy_amount = settings.subsidy_amount;
                g_attempts = 0;
            }
            // Schedule next update
            current_time = absl::Now();
            g_last_settings_fetch = current_time;
            g_next_settings_fetch = current_time + absl::Seconds(5);
        }

        std::unique_lock<std::mutex> lock(g_state_mutex);
        g_update_thread_cv.wait_until(lock, absl::ToChronoTime(std::min(g_next_rng_update, g_next_settings_fetch)));

        current_time = absl::Now();
        if (current_time >= g_next_rng_update) {
            update_rng = true;
        }
        if (current_time >= g_next_settings_fetch) {
            fetch_settings = true;
        }
    }
}

ABSL_FLAG(std::string, wallet, "wallet.log", "filename to place generated webcash claim codes");

int main(int argc, char **argv)
{
    using std::to_string;

    absl::SetProgramUsageMessage(absl::StrCat("Webcash mining daemon.\n", argv[0]));
    absl::ParseCommandLine(argc, argv);
    const std::string wallet_filename = absl::GetFlag(FLAGS_wallet);

    RandomInit();
    if (!Random_SanityCheck()) {
        std::cerr << "Error: RNG sanity check failed. RNG is not secure." << std::endl;
        return 1;
    }

    const std::string algo = SHA256AutoDetect();
    std::cout << "Using SHA256 algorithm '" << algo << "'." << std::endl;

    ProtocolSettings settings;
    if (!get_protocol_settings(settings)) {
        std::cerr << "Error: could not fetch protocol settings from server; exiting" << std::endl;
        return 1;
    }
    std::cout << "server says"
              << " difficulty=" << settings.difficulty
              << " ratio=" << settings.ratio
              << std::endl;
    g_difficulty = settings.difficulty;
    g_mining_amount = settings.mining_amount;
    g_subsidy_amount = settings.subsidy_amount;

    // Launch thread to update RNG and protocol settings in the background.
    std::thread update_thread(update_thread_func);

    bool done = false;
    while (!done) {
        SecretWebcash keep;
        keep.amount = g_mining_amount - g_subsidy_amount;
        GetStrongRandBytes(keep.sk.begin(), 32);

        SecretWebcash subsidy;
        subsidy.amount = g_subsidy_amount;
        GetStrongRandBytes(subsidy.sk.begin(), 32);

        std::string prefix = absl::StrCat("{\"webcash\": [\"", to_string(keep), "\", \"", to_string(subsidy), "\"], \"subsidy\": [\"", to_string(subsidy), "\"], \"nonce\": ");

        for (int i = 0; i < 10000; ++i) {
            ++g_attempts;

            std::string preimage = absl::Base64Escape(absl::StrCat(prefix, to_string(i), "}"));
            uint256 hash;
            CSHA256()
                .Write((unsigned char*)preimage.data(), preimage.size())
                .Finalize(hash.begin());

            if (!(*(const uint16_t*)hash.begin()) && check_proof_of_work(hash, g_difficulty)) {
                BIGNUM bn;
                BN_init(&bn);
                BN_bin2bn((const uint8_t*)hash.begin(), 32, &bn);
                char* work = BN_bn2dec(&bn);
                BN_free(&bn);

                std::string webcash = to_string(keep);
                std::cout << "GOT SOLUTION!!! " << preimage << " " << absl::StrCat("0x" + absl::BytesToHexString(absl::string_view((const char*)hash.begin(), 32))) << " " << webcash << std::endl;

                httplib::Client cli("https://webcash.tech");
                cli.set_read_timeout(60, 0); // 60 seconds
                cli.set_write_timeout(60, 0); // 60 seconds
                auto r = cli.Post(
                    "/api/v1/mining_report",
                    absl::StrCat("{\"preimage\": \"", preimage, "\", \"work\": ", work, "}"),
                    "application/json");
                if (!r) {
                    std::cerr << "Error: returned invalid response to MiningReport request: " << r.error() << std::endl;
                    continue;
                }
                if (r->status != 200) {
                    // server error, or difficulty changed against us
                    std::cerr << "Error: returned invalid response to MiningReport request: status_code=" << r->status << ", text='" << r->body << "'" << std::endl;
                    {
                        const std::lock_guard<std::mutex> lock(g_state_mutex);
                        g_next_settings_fetch = absl::Now();
                    }
                    g_update_thread_cv.notify_all();
                    continue;
                }

                {
                    std::ofstream wallet_log(wallet_filename, std::ofstream::app);
                    wallet_log << webcash << std::endl;
                    wallet_log.flush();
                }

                // Generate new Webcash secrets, so that we don't reuse a secret
                // if we happen to generate two solutions back-to-back.
                GetStrongRandBytes(keep.sk.begin(), 32);
                GetStrongRandBytes(subsidy.sk.begin(), 32);

                UniValue o;
                o.read(r->body);
                const UniValue& difficulty = o["difficulty_target"];
                if (difficulty.isNum()) {
                    int bits = difficulty.get_int();
                    int old_bits = g_difficulty.exchange(bits);
                    if (bits != old_bits) {
                        std::cout << "Difficulty adjustment occured! Server says difficulty=" << bits << std::endl;
                    }
                }
            }
        }
    }

    return 0;
}

// End of File
