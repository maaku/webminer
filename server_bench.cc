// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <benchmark/benchmark.h>

#include <future>
#include <thread>
#include <vector>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

#include <drogon/HttpAppFramework.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>

#include <json/json.h>

#include "async.h"
#include "crypto/sha256.h"
#include "random.h"
#include "webcash.h"

using Json::ValueType::objectValue;

std::thread g_event_loop_thread;
std::atomic<bool> g_event_loop_setup = false;
std::vector<SecretWebcash> g_utxos;

static void TeardownServer();
static void SetupServer(const benchmark::State& state) {
    // Only run the first time
    bool already_setup = g_event_loop_setup.exchange(true);
    if (already_setup) {
        return;
    }
    // Create a promise which will only be fulfilled after starting the main
    // event loop.
    std::promise<void> p1;
    std::future<void> f1 = p1.get_future();
    g_event_loop_thread = std::thread([&]() {
        // Configure the number of worker threads
        drogon::app().setThreadNum(get_num_workers());
        // Set HTTP listener address and port
        drogon::app().addListener("127.0.0.1", 8000);
        // Queue the promise for fulfillment after the event loop is started.
        drogon::app().getLoop()->queueInLoop([&p1]() {
            p1.set_value();
        });
        // Start the main event loop.
        drogon::app().run();
    });
    // While that is starting up, detect which sha256 engine we should use.
    SHA256AutoDetect();
    // Wait for the event loop to begin processing.
    f1.get();
    // Schedule server to be shut down
    std::atexit(TeardownServer);
}

static void TeardownServer() {
    // Terminate the main event loop and wait for its thread to quit.
    drogon::app().getLoop()->queueInLoop([]() {
        drogon::app().quit();
    });
    g_event_loop_thread.join();
}

static void Server_stats(benchmark::State& state) {
    httplib::Client cli("http://localhost:8000");
    cli.set_read_timeout(60, 0); // 60 seconds
    cli.set_write_timeout(60, 0); // 60 seconds
    for (auto _ : state) {
        auto r = cli.Get("/stats");
        assert(r);
        assert(r->status == 200);
    }
}
BENCHMARK(Server_stats)->Setup(SetupServer);

static void Server_replace(benchmark::State& state) {
    // Setup RPC client to communicate with server
    httplib::Client cli("http://localhost:8000");
    cli.set_read_timeout(60, 0); // 60 seconds
    cli.set_write_timeout(60, 0); // 60 seconds

    static std::array<std::string, 256> base;
    static std::atomic<bool> first_run = true;
    if (first_run.exchange(false)) {
        // Pregenerate 32 webcash claim codes that we will need for each of the (up to) 32 threads.
        for (auto& wc_str : base) {
            wc_str = absl::StrCat("e742.1875:secret:", absl::BytesToHexString(absl::string_view((char*)GetRandHash().begin(), 32)));
        }
        // Submit an initial solution to generate some webcash for use.
        static const std::string preimage = absl::Base64Escape("{\"legalese\": {\"terms\": true}, \"webcash\": [\"e190000:secret:b0e7525b420bc6efa5c356d0bb707d96a9d599c5c218134bd0f1dc5cf107e213\", \"e10000:secret:301b4fe3587ac6a871c6c7d4e06595d4eab9572a0515fe7295067d4e52772ed2\"], \"subsidy\": [\"e10000:secret:301b4fe3587ac6a871c6c7d4e06595d4eab9572a0515fe7295067d4e52772ed2\"], \"difficulty\": 28, \"nonce\":      1366624}");
        auto r = cli.Post(
            "/api/v1/mining_report",
            absl::StrCat("{"
                "\"preimage\": \"", preimage, "\","
                "\"legalese\": {"
                    "\"terms\": true"
                "}"
            "}"),
            "application/json");
        assert(r);
        assert(r->status == 200);
        r = cli.Post(
        "/api/v1/replace",
        absl::StrCat("{"
            "\"legalese\": {"
                "\"terms\": true"
            "},"
            "\"webcashes\": ["
                "\"e190000:secret:b0e7525b420bc6efa5c356d0bb707d96a9d599c5c218134bd0f1dc5cf107e213\""
            "],"
            "\"new_webcashes\": [\"",
                absl::StrJoin(base, "\",\""),
            "\"]"
        "}"),
        "application/json");
    }

    // Generate 4 random claim codes to use for transaction replacements in this run.
    static const std::array<std::string, 4> wc = {
        absl::StrCat("e185.546875:secret:", absl::BytesToHexString(absl::string_view((char*)GetRandHash().begin(), 32))),
        absl::StrCat("e185.546875:secret:", absl::BytesToHexString(absl::string_view((char*)GetRandHash().begin(), 32))),
        absl::StrCat("e185.546875:secret:", absl::BytesToHexString(absl::string_view((char*)GetRandHash().begin(), 32))),
        absl::StrCat("e185.546875:secret:", absl::BytesToHexString(absl::string_view((char*)GetRandHash().begin(), 32))),
    };

    // Split generated output in half, so we have two UTXOs
    auto r = cli.Post(
        "/api/v1/replace",
        absl::StrCat("{"
            "\"legalese\": {"
                "\"terms\": true"
            "},"
            "\"webcashes\": ["
                "\"", base[state.thread_index()], "\""
            "],"
            "\"new_webcashes\": ["
                "\"", wc[0], "\","
                "\"", wc[1], "\""
            "]"
        "}"),
        "application/json");
    assert(r && r->status == 200);

    // The replacement requests, each of which have two inputs and two outputs,
    // and cycle between them.
    static const std::array<std::string, 2> replacements = {
        absl::StrCat("{"
            "\"legalese\": {"
                "\"terms\": true"
            "},"
            "\"webcashes\": ["
                "\"", wc[0], "\","
                "\"", wc[1], "\""
            "],"
            "\"new_webcashes\": ["
                "\"", wc[2], "\","
                "\"", wc[3], "\""
            "]"
        "}"),
        absl::StrCat("{"
            "\"legalese\": {"
                "\"terms\": true"
            "},"
            "\"webcashes\": ["
                "\"", wc[2], "\","
                "\"", wc[3], "\""
            "],"
            "\"new_webcashes\": ["
                "\"", wc[0], "\","
                "\"", wc[1], "\""
            "]"
        "}"),
    };

    size_t i = 0;
    for (auto _ : state) {
        r = cli.Post(
            "/api/v1/replace",
            replacements[i++ & 1],
            "application/json");
        assert(r && r->status == 200);
    }

    // Replace used webcash with the original secret, so the benchmark code can
    // be run again.
    r = cli.Post(
        "/api/v1/replace",
        absl::StrCat("{"
            "\"legalese\": {"
                "\"terms\": true"
            "},"
            "\"webcashes\": ["
                "\"", wc[2*(i & 1)], "\","
                "\"", wc[2*(i & 1) + 1], "\""
            "],"
            "\"new_webcashes\": ["
                "\"", base[state.thread_index()], "\""
            "]"
        "}"),
        "application/json");
    assert(r && r->status == 200);
}
BENCHMARK(Server_replace)->Setup(SetupServer)->ThreadRange(1, 256);

// End of File
