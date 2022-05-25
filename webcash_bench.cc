// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <benchmark/benchmark.h>

#include "webcash.h"

// Benchmark serialization and deserialization of SecretWebcash
static void SecretWebcash_to_string(benchmark::State& state) {
    using std::to_string;
    std::string wc_str;
    SecretWebcash wc;
    assert(wc.parse("e190000:secret:f9328d45619ccc052cd96c9408e322fd2ad60adc85d303e771f6b153ab2ed089"));
    for (auto _ : state) {
        wc_str = to_string(wc);
    }
}
BENCHMARK(SecretWebcash_to_string);

static void SecretWebcash_parse(benchmark::State& state) {
    std::string wc_str = "e190000:secret:f9328d45619ccc052cd96c9408e322fd2ad60adc85d303e771f6b153ab2ed089";
    SecretWebcash wc;
    for (auto _ : state) {
        wc.parse(wc_str);
    }
}
BENCHMARK(SecretWebcash_parse);

static void SecretWebcash_round_trip(benchmark::State& state) {
    using std::to_string;
    std::string wc_str = "e190000:secret:f9328d45619ccc052cd96c9408e322fd2ad60adc85d303e771f6b153ab2ed089";
    SecretWebcash wc;
    for (auto _ : state) {
        wc.parse(wc_str);
        wc_str = to_string(wc);
    }
}
BENCHMARK(SecretWebcash_round_trip);

static void PublicWebcash_to_string(benchmark::State& state) {
    using std::to_string;
    std::string wc_str;
    PublicWebcash wc;
    assert(wc.parse("e190000:public:9a8a1ac24dd10f243c9ac05eb7093d130a032d5a31ae648014a33f8e02d47fcf"));
    for (auto _ : state) {
        wc_str = to_string(wc);
    }
}
BENCHMARK(PublicWebcash_to_string);

static void PublicWebcash_parse(benchmark::State& state) {
    std::string wc_str = "e190000:public:9a8a1ac24dd10f243c9ac05eb7093d130a032d5a31ae648014a33f8e02d47fcf";
    PublicWebcash wc;
    for (auto _ : state) {
        wc.parse(wc_str);
    }
}
BENCHMARK(PublicWebcash_parse);

static void PublicWebcash_round_trip(benchmark::State& state) {
    using std::to_string;
    std::string wc_str = "e190000:public:9a8a1ac24dd10f243c9ac05eb7093d130a032d5a31ae648014a33f8e02d47fcf";
    PublicWebcash wc;
    for (auto _ : state) {
        wc.parse(wc_str);
        wc_str = to_string(wc);
    }
}
BENCHMARK(PublicWebcash_round_trip);

static void PublicWebcash_from_secret(benchmark::State& state) {
    SHA256AutoDetect();
    SecretWebcash sk;
    PublicWebcash pk;
    assert(sk.parse("e190000:secret:f9328d45619ccc052cd96c9408e322fd2ad60adc85d303e771f6b153ab2ed089"));
    for (auto _ : state) {
        pk = PublicWebcash(sk);
    }
}
BENCHMARK(PublicWebcash_from_secret);

// End of File
