// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <iostream>

#include <deque>
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
#include "wallet.h"

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

int get_apparent_difficulty(const uint256& hash)
{
    int bits = 0;
    for (int i = 0; i < 32; ++i) {
        const unsigned char c = hash.begin()[i];
        if (c == 0x00) {
            bits += 8;
            continue;
        }
        if (c == 0x01) return bits + 7;
        if (c <= 0x03) return bits + 6;
        if (c <= 0x07) return bits + 5;
        if (c <= 0x0f) return bits + 4;
        if (c <= 0x1f) return bits + 3;
        if (c <= 0x3f) return bits + 2;
        if (c <= 0x7f) return bits + 1;
        break;
    }
    return bits;
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

struct Solution
{
    uint256 hash;
    std::string preimage;
    SecretWebcash webcash;

    Solution() = default;
    Solution(const uint256& hashIn, const std::string& preimageIn, const SecretWebcash& webcashIn) : hash(hashIn), preimage(preimageIn), webcash(webcashIn) {}
};

std::mutex g_state_mutex;
std::unique_ptr<Wallet> g_wallet;
std::deque<Solution> g_solutions;
std::atomic<int> g_difficulty{16};
std::atomic<int64_t> g_mining_amount{20000};
std::atomic<int64_t> g_subsidy_amount{1000};
std::atomic<int64_t> g_attempts{0};
absl::Time g_last_rng_update{absl::UnixEpoch()};
absl::Time g_next_rng_update{absl::UnixEpoch()};
absl::Time g_last_settings_fetch{absl::UnixEpoch()};
absl::Time g_next_settings_fetch{absl::UnixEpoch()};

ABSL_FLAG(std::string, webcashlog, "webcash.log", "filename to place generated webcash claim codes");
ABSL_FLAG(std::string, orphanlog, "orphans.log", "filename to place solved proof-of-works the server rejects, and their associated webcash claim codes");
ABSL_FLAG(std::string, walletfile, "default_wallet", "base filename of wallet files");

void update_thread_func()
{
    using std::to_string;

    const std::string webcash_log_filename = absl::GetFlag(FLAGS_webcashlog);
    const std::string orphan_log_filename = absl::GetFlag(FLAGS_orphanlog);

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
            }
            // Schedule next update
            current_time = absl::Now();
            g_last_settings_fetch = current_time;
            g_next_settings_fetch = current_time + absl::Seconds(15);
        }

        while (true) {
            // Fetch a solved proof-of-work in FIFO order
            Solution soln;
            {
                const std::lock_guard<std::mutex> lock(g_state_mutex);
                if (g_solutions.empty()) {
                    break;
                }
                soln = std::move(g_solutions.front());
                g_solutions.pop_front();
            }

            // Convert hash to decimal notation
            BIGNUM bn;
            BN_init(&bn);
            BN_bin2bn((const uint8_t*)soln.hash.begin(), 32, &bn);
            char* work = BN_bn2dec(&bn);
            BN_free(&bn);

            // Submit the solved proof-of-work
            httplib::Client cli("https://webcash.tech");
            cli.set_read_timeout(60, 0); // 60 seconds
            cli.set_write_timeout(60, 0); // 60 seconds
            auto r = cli.Post(
                "/api/v1/mining_report",
                absl::StrCat("{\"preimage\": \"", soln.preimage, "\", \"work\": ", work, "}"),
                "application/json");

            // Handle network errors by aborting further processing
            if (!r) {
                std::cerr << "Error: returned invalid response to MiningReport request: " << r.error() << std::endl;
                std::cerr << "Possible transient error, or server timeout?  Waiting to re-attempt.";
                const std::lock_guard<std::mutex> lock(g_state_mutex);
                g_solutions.push_front(soln);
                break;
            }

            // Parse response
            UniValue o;
            o.read(r->body);

            // Handle server rejection by saving the proof-of-work
            // solution to the orphan log.
            if (r->status != 200 && !(r->status == 400 && o.isObject() && o.exists("error") && o["error"].get_str() == "Didn't use a new secret value.")) {
                // server error, or difficulty changed against us
                std::cerr << "Error: returned invalid response to MiningReport request: status_code=" << r->status << ", text='" << r->body << "'" << std::endl;
                g_next_settings_fetch = absl::Now();
                // Save the solution to the orphan log
                std::ofstream orphan_log(orphan_log_filename, std::ofstream::app);
                orphan_log << soln.preimage << ' ' << absl::BytesToHexString(absl::string_view((const char*)soln.hash.begin(), 32)) << ' ' << to_string(soln.webcash) << " difficulty=" << get_apparent_difficulty(soln.hash) << std::endl;
                orphan_log.flush();
                continue;
            }

            // Update difficulty
            const UniValue& difficulty = o["difficulty_target"];
            if (difficulty.isNum()) {
                int bits = difficulty.get_int();
                int old_bits = g_difficulty.exchange(bits);
                if (bits != old_bits) {
                    std::cout << "Difficulty adjustment occured! Server says difficulty=" << bits << std::endl;
                }
            }

            // Claim the coin with our wallet
            if (!g_wallet->Insert(soln.webcash)) {
                // Save the successfully submitted webcash to the log, since we
                // were unable to add it to the wallet.
                std::ofstream webcash_log(webcash_log_filename, std::ofstream::app);
                webcash_log << to_string(soln.webcash) << std::endl;
                webcash_log.flush();
            }
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

void mining_thread_func(int id)
{
    using std::to_string;

    bool done = false;
    while (!done) {
        SecretWebcash keep;
        keep.amount = g_mining_amount - g_subsidy_amount;
        GetStrongRandBytes(keep.sk.begin(), 32);

        SecretWebcash subsidy;
        subsidy.amount = g_subsidy_amount;
        GetStrongRandBytes(subsidy.sk.begin(), 32);

        std::string subsidy_str = to_string(subsidy);
        std::string prefix = absl::StrCat("{\"webcash\": [\"", to_string(keep), "\", \"", subsidy_str, "\"], \"subsidy\": [\"", subsidy_str, "\"], \"nonce\": ");
        // Extend the prefix to be a multiple of 48 in size...
        prefix.resize(48 * (1 + prefix.size() / 48), ' ');
        prefix.back() = '1';
        // ...which becomes 64 bytes when base64 encoded.
        std::string prefix_b64 = absl::Base64Escape(prefix);
        // And 64 bytes is the SHA256 block size.
        CSHA256 midstate;
        midstate.Write((unsigned char*)prefix_b64.data(), prefix_b64.size());

        for (int i = 0; i < 262144; ++i) {
            ++g_attempts;

            std::string nonce_b64 = absl::Base64Escape(absl::StrCat(to_string(i), "}"));
            uint256 hash;
            CSHA256(midstate)
                .Write((unsigned char*)nonce_b64.data(), nonce_b64.size())
                .Finalize(hash.begin());

            if (!(*(const uint16_t*)hash.begin()) && check_proof_of_work(hash, g_difficulty)) {
                std::cout << "GOT SOLUTION!!! " << prefix_b64 << nonce_b64 << " " << absl::StrCat("0x" + absl::BytesToHexString(absl::string_view((const char*)hash.begin(), 32))) << " " << to_string(keep) << std::endl;

                // Add solution to the queue, and wake up the server
                // communication thread.
                {
                    const std::lock_guard<std::mutex> lock(g_state_mutex);
                    g_solutions.emplace_back(hash, absl::StrCat(prefix_b64, nonce_b64), keep);
                }
                g_update_thread_cv.notify_all();

                // Generate new Webcash secrets, so that we don't reuse a secret
                // if we happen to generate two solutions back-to-back.
                break;
            }
        }
    }

}

ABSL_FLAG(unsigned, workers, 0, "number of mining threads to spawn");

int main(int argc, char **argv)
{
    absl::SetProgramUsageMessage(absl::StrCat("Webcash mining daemon.\n", argv[0]));
    absl::ParseCommandLine(argc, argv);
    int num_workers = absl::GetFlag(FLAGS_workers);
    if (num_workers > 256) {
        std::cerr << "Error: --workers cannot be larger than 256" << std::endl;
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
    {
        // Touch the wallet file, which will create it if it doesn't
        // already exist.  The file locking primitives assume that the
        // file exists, so we need to create here first.  It also allows
        // the user to see the file even before a successful
        // proof-of-work solution has been found.
        std::ofstream webcash_log(absl::GetFlag(FLAGS_webcashlog), std::ofstream::app);
        webcash_log.flush();
    }
    {
        // Do the same for the orphan log as well.
        std::ofstream orphan_log(absl::GetFlag(FLAGS_orphanlog), std::ofstream::app);
        orphan_log.flush();
    }

    // Open the wallet file, which will throw an error if the walletfile
    // parameter is unusable.
    g_wallet = std::unique_ptr<Wallet>(new Wallet(absl::GetFlag(FLAGS_walletfile)));
    if (!g_wallet) {
        std::cerr << "Error: Unable to open wallet." << std::endl;
        return 1;
    }

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

    // Launch thread to update RNG and protocol settings, and to
    // submit work in the background.
    std::thread update_thread(update_thread_func);

    // Launch worker threads
    std::vector<std::thread> mining_threads;
    mining_threads.reserve(num_workers);
    std::cout << "Spawning " << num_workers << " worker threads" << std::endl;
    for (int i = 0; i < num_workers; ++i) {
        mining_threads.emplace_back(mining_thread_func, i);
    }

    // Wait for mining threads to exit
    while (!mining_threads.empty()) {
        mining_threads.back().join();
        mining_threads.pop_back();
    }

    // Wait for server communication thread to finish
    update_thread.join();

    return 0;
}

// End of File
