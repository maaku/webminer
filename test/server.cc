// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include <httplib.h>

#include "async.h"
#include "random.h"
#include "server.h"

// This code is copied from the server benchmarking setup and teardown code,
// with minimal changes.  We should merge the two somehow.
std::thread g_event_loop_thread;
std::atomic<bool> g_event_loop_setup = false;

static void TeardownServer();
static void SetupServer() {
    // Only run the first time
    bool already_setup = g_event_loop_setup.exchange(true);
    if (already_setup) {
        // Clear the database
        webcash::resetDb();
        return;
    }
    // Create a promise which will only be fulfilled after starting the main
    // event loop.
    std::promise<void> p1;
    std::future<void> f1 = p1.get_future();
    g_event_loop_thread = std::thread([&]() {
        // Disable logging
        webcash::state().logging = false;
        // Create the database connection
        int num_workers = get_num_workers();
        drogon::app().createDbClient(
            "postgresql", // dbType
            "localhost", // host
            5432,        // port
            "postgres",  // databaseName
            "postgres",  // username
            "mysecretpassword",  // password
            num_workers, // connectionNum
            "server_test", // filename
            "default",   // name
            false,       // isFast
            "utf8",      // characterSet
            10.0         // timeout
        );
        // Setup the database
        webcash::upgradeDb();
        // Configure the number of worker threads
        drogon::app().setThreadNum(num_workers);
        // Set HTTP listener address and port
        drogon::app().addListener("127.0.0.1", 8000);
        // Queue the promise for fulfillment after the event loop is started.
        drogon::app().getLoop()->queueInLoop([&p1]() {
            // Signal that the event loop is running
            p1.set_value();
        });
        // Start the main event loop.
        drogon::app().run();
    });
    // While that is starting up, detect which sha256 engine we should use.
    SHA256AutoDetect();
    // Wait for the event loop to begin processing.
    f1.get();
    // Clear the database
    webcash::resetDb();
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

TEST(server, connection) {
    // Setup server and begin listening
    SetupServer();
    // Setup RPC client to communicate with server
    httplib::Client cli("http://localhost:8000");
    cli.set_read_timeout(60, 0); // 60 seconds
    cli.set_write_timeout(60, 0); // 60 seconds
    // Get the mining difficulty
    auto r = cli.Get("/api/v1/target");
    // Check we got a valid response
    EXPECT_NE(r, nullptr);
    EXPECT_EQ(r->status, 200);
}

TEST(server, stats) {
    // Setup server and begin listening
    SetupServer();

    // Check initial stats
    auto now = absl::Now();
    webcash::state().genesis = now;
    auto stats = webcash::state().getStats(now);
    EXPECT_EQ(stats.timestamp, now);
    EXPECT_EQ(stats.total_circulation, absl::MakeInt128(0, 0));
    EXPECT_EQ(stats.expected_circulation, absl::MakeInt128(0, 0));
    EXPECT_EQ(stats.num_reports, 0);
    EXPECT_EQ(stats.num_replace, 0);
    EXPECT_EQ(stats.num_unspent, 0);
    EXPECT_EQ(stats.mining_amount, Amount(20000000000000ULL));
    EXPECT_EQ(stats.subsidy_amount, Amount(1000000000000ULL));
    EXPECT_EQ(stats.epoch, 0);
    EXPECT_EQ(stats.difficulty, 28);
    // "Wait" 10 seconds and see that the expected_circulation goes up
    stats = webcash::state().getStats(now + absl::Seconds(10));
    EXPECT_EQ(stats.expected_circulation, absl::MakeInt128(0, 20000000000000ULL));

    // Setup RPC client to communicate with server
    httplib::Client cli("http://localhost:8000");
    cli.set_read_timeout(60, 0); // 60 seconds
    cli.set_write_timeout(60, 0); // 60 seconds
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
    EXPECT_NE(r, nullptr);
    EXPECT_EQ(r->status, 200);

    // Check that genesis has been advanced to the time of submission
    EXPECT_LT(now, webcash::state().genesis);

    // Check stats after one mining report
    stats = webcash::state().getStats(webcash::state().genesis);
    EXPECT_EQ(stats.timestamp, webcash::state().genesis);
    EXPECT_EQ(stats.total_circulation, absl::MakeInt128(0, 20000000000000ULL));
    EXPECT_EQ(stats.expected_circulation, absl::MakeInt128(0, 0));
    EXPECT_EQ(stats.num_reports, 1);
    EXPECT_EQ(stats.num_replace, 0);
    EXPECT_EQ(stats.num_unspent, 2);
    EXPECT_EQ(stats.mining_amount, Amount(20000000000000ULL));
    EXPECT_EQ(stats.subsidy_amount, Amount(1000000000000ULL));
    EXPECT_EQ(stats.epoch, 0);
    EXPECT_EQ(stats.difficulty, 28);

    std::array<std::string, 256> secrets;
    for (auto& wc_str : secrets) {
        wc_str = absl::StrCat("e742.1875:secret:", absl::BytesToHexString(absl::string_view((char*)GetRandHash().begin(), 32)));
    }
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
                absl::StrJoin(secrets, "\",\""),
            "\"]"
        "}"),
        "application/json");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->status, 200);

    // Check stats after a replacement
    stats = webcash::state().getStats(webcash::state().genesis + absl::Seconds(20));
    EXPECT_EQ(stats.timestamp, webcash::state().genesis + absl::Seconds(20));
    EXPECT_EQ(stats.total_circulation, absl::MakeInt128(0, 20000000000000ULL));
    EXPECT_EQ(stats.expected_circulation, absl::MakeInt128(0, 40000000000000ULL));
    EXPECT_EQ(stats.num_reports, 1);
    EXPECT_EQ(stats.num_replace, 1);
    EXPECT_EQ(stats.num_unspent, 257);
    EXPECT_EQ(stats.mining_amount, Amount(20000000000000ULL));
    EXPECT_EQ(stats.subsidy_amount, Amount(1000000000000ULL));
    EXPECT_EQ(stats.epoch, 0);
    EXPECT_EQ(stats.difficulty, 28);
}

TEST(server, input_as_output) {
    // Setup server and begin listening
    SetupServer();

    // Setup RPC client to communicate with server
    httplib::Client cli("http://localhost:8000");
    cli.set_read_timeout(60, 0); // 60 seconds
    cli.set_write_timeout(60, 0); // 60 seconds

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
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->status, 200);
    EXPECT_EQ(webcash::state().num_replace, 0);

    // Attempt replace an output with itself
    r = cli.Post(
        "/api/v1/replace",
        absl::StrCat("{"
            "\"legalese\": {"
                "\"terms\": true"
            "},"
            "\"webcashes\": ["
                "\"e190000:secret:b0e7525b420bc6efa5c356d0bb707d96a9d599c5c218134bd0f1dc5cf107e213\""
            "],"
            "\"new_webcashes\": [",
                "\"e190000:secret:b0e7525b420bc6efa5c356d0bb707d96a9d599c5c218134bd0f1dc5cf107e213\""
            "]"
        "}"),
        "application/json");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->status, 500);
    EXPECT_EQ(webcash::state().num_replace, 0);

    // Attempt the same, but with differing amounts
    r = cli.Post(
        "/api/v1/replace",
        absl::StrCat("{"
            "\"legalese\": {"
                "\"terms\": true"
            "},"
            "\"webcashes\": ["
                "\"e190000:secret:b0e7525b420bc6efa5c356d0bb707d96a9d599c5c218134bd0f1dc5cf107e213\""
            "],"
            "\"new_webcashes\": [",
                "\"e95000:secret:312e701fc5cd1f0db431812c5c995d9a69d707bb0d653c5afe6cb024b5257e0b\","
                "\"e95000:secret:b0e7525b420bc6efa5c356d0bb707d96a9d599c5c218134bd0f1dc5cf107e213\""
            "]"
        "}"),
        "application/json");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->status, 500);
    EXPECT_EQ(webcash::state().num_replace, 0);

    // Remove the secret that matches the input, but this time leave off the
    // legalese acceptance.
    r = cli.Post(
        "/api/v1/replace",
        absl::StrCat("{"
            "\"webcashes\": ["
                "\"e190000:secret:b0e7525b420bc6efa5c356d0bb707d96a9d599c5c218134bd0f1dc5cf107e213\""
            "],"
            "\"new_webcashes\": [",
                "\"e190000:secret:312e701fc5cd1f0db431812c5c995d9a69d707bb0d653c5afe6cb024b5257e0b\""
            "]"
        "}"),
        "application/json");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->status, 500);
    EXPECT_EQ(webcash::state().num_replace, 0);

    // Put the legalese back in and we're A-OK!
    r = cli.Post(
        "/api/v1/replace",
        absl::StrCat("{"
            "\"legalese\": {"
                "\"terms\": true"
            "},"
            "\"webcashes\": ["
                "\"e190000:secret:b0e7525b420bc6efa5c356d0bb707d96a9d599c5c218134bd0f1dc5cf107e213\""
            "],"
            "\"new_webcashes\": [",
                "\"e190000:secret:312e701fc5cd1f0db431812c5c995d9a69d707bb0d653c5afe6cb024b5257e0b\""
            "]"
        "}"),
        "application/json");
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->status, 200);
    EXPECT_EQ(webcash::state().num_replace, 1);
}

// End of File
