// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "webcash.h"

#include <string>

#include <stdint.h>

#include "absl/numeric/int128.h"

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"

// Requires an input that is a fractional-precision decimal with no more than 8
// digits past the decimal point, with a leading minus sign if the value is
// negative.  Extremely ficky parser that only values that could be output by
// to_string(const &Amount) defined below.
bool Amount::parse(const absl::string_view& str) {
    // Sanity: no empty strings allowed.
    if (str.empty()) {
        return false;
    }
    // Sanity: no embedded NUL characters allowed.
    if (str.size() != strnlen(str.data(), str.size())) {
        return false;
    }

    auto pos = str.begin();
    auto end = str.end();
    absl::int128 i = 0;

    if (*pos == '"') {
        do {
            --end;
        } while (*end != '"');
        // An opening quote and nothing else is not a valid encoding.
        if (pos == end) {
            return false;
        }
        // Advance pos past the opening quote.
        ++pos;
    }

    bool negative = (*pos == '-');
    if (negative) {
        ++pos;
        // A single minus sign is not a valid encoding.
        if (pos == end) {
            return false;
        }
    }

    // A leading zero is required, even for fractional amounts.
    if (!absl::ascii_isdigit(*pos)) {
        return false;
    }
    // But in that case the next character must be a decimal point.
    if (pos[0] == '0' && (pos + 1) != end && pos[1] != '.') {
        return false;
    }

    for (; pos != end && absl::ascii_isdigit(*pos); ++pos) {
        i *= 10;
        i += (*pos - '0');
        // Overflow check
        if (i > std::numeric_limits<int64_t>::max()) {
            return false;
        }
    }

    // Fractional digits are optional.
    int j = 0;
    if (pos != end) {
        // Skip past the decimal point.
        if (*pos != '.') {
            return false;
        }
        ++pos;
        // If there is a decimal point, there must be at least one digit.
        if (pos == end) {
            return false;
        }
        // Read up to 8 digits
        for (; j < 8 && pos != end; ++j, ++pos) {
            if (!absl::ascii_isdigit(*pos)) {
                return false;
            }
            i *= 10;
            i += (*pos - '0');
        }
        // We must now be at the end of the input
        if (pos != end) {
            return false;
        }
    }
    for (; j < 8; ++j) {
        i *= 10;
    }
    // Overflow check
    if (i > std::numeric_limits<int64_t>::max()) {
        return false;
    }

    i64 = static_cast<int64_t>(i);
    if (negative) {
        i64 = -i64;
    }
    return true;
}

// Returns the amount formatted as a fixed-precision decimal with 8 fractional
// digits, as per webcash tradition.  Any terminal zero fractional digits up to
// and including the decimal place itself are not output.
//     e.g. 3000000 is rendered as "0.03"
std::string to_string(const Amount& amt) {
    using std::to_string;
    std::lldiv_t div = std::lldiv(std::abs(amt.i64), 100000000LL);
    std::string res = (amt.i64 < 0) ? "-" : "";
    res += to_string(div.quot);
    if (div.rem) {
        std::string frac = to_string(div.rem);
        res.push_back('.');
        res.insert(res.end(), 8 - frac.length(), '0');
        res += frac;
        while (res.back() == '0') {
            res.pop_back();
        }
    }
    return res;
}

template<class Str>
static std::string webcash_string(Amount amount, const absl::string_view& type, const Str& hex)
{
    using std::to_string;
    if (amount.i64 < 0) {
        amount.i64 = 0;
    }
    return absl::StrCat("e", to_string(amount), ":", type, ":", hex);
}

std::string to_string(const SecretWebcash& esk)
{
    return webcash_string(esk.amount, "secret", esk.sk);
}

std::string to_string(const PublicWebcash& epk)
{
    std::string hex = absl::BytesToHexString(absl::string_view((const char*)epk.pk.data(), epk.pk.size()));
    return webcash_string(epk.amount, "public", hex);
}


// End of File
