// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include <httplib.h>

#include "async.h"
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
            "test_webcash", // filename
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
    // Clear the database
    webcash::resetDb();
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

// End of File
