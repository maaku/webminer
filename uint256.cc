// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include "uint256.h"

#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"

#include <string.h>

template <unsigned int BITS>
base_blob<BITS>::base_blob(const std::vector<unsigned char>& vch)
{
    assert(vch.size() == sizeof(m_data));
    memcpy(m_data, vch.data(), sizeof(m_data));
}

template <unsigned int BITS>
std::string base_blob<BITS>::GetHex() const
{
    uint8_t m_data_rev[WIDTH];
    for (int i = 0; i < WIDTH; ++i) {
        m_data_rev[i] = m_data[WIDTH - 1 - i];
    }
    return absl::BytesToHexString(absl::string_view((char*)m_data_rev, WIDTH));
}

// Copied from absl/strings/escaping.cc
inline unsigned char hex_digit_to_int(unsigned char c) {
    static_assert('0' == 0x30 && 'A' == 0x41 && 'a' == 0x61,
                  "Character set must be ASCII.");
    assert(absl::ascii_isxdigit(c));
    if (c > '9') {
        c += 9;
    }
    return c & 0xf;
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const char* psz)
{
    memset(m_data, 0, sizeof(m_data));

    // skip leading spaces
    while (absl::ascii_isspace(*psz))
        psz++;

    // skip 0x
    if (psz[0] == '0' && absl::ascii_tolower(psz[1]) == 'x')
        psz += 2;

    // hex string to uint
    size_t digits = 0;
    while (absl::ascii_isxdigit(psz[digits]))
        digits++;
    unsigned char* p1 = (unsigned char*)m_data;
    unsigned char* pend = p1 + WIDTH;
    while (digits > 0 && p1 < pend) {
        *p1 = hex_digit_to_int(psz[--digits]);
        if (digits > 0) {
            *p1 |= (hex_digit_to_int(psz[--digits]) << 4);
            p1++;
        }
    }
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const std::string& str)
{
    SetHex(str.c_str());
}

template <unsigned int BITS>
std::string base_blob<BITS>::ToString() const
{
    return (GetHex());
}

// Explicit instantiations for base_blob<160>
template base_blob<160>::base_blob(const std::vector<unsigned char>&);
template std::string base_blob<160>::GetHex() const;
template std::string base_blob<160>::ToString() const;
template void base_blob<160>::SetHex(const char*);
template void base_blob<160>::SetHex(const std::string&);

// Explicit instantiations for base_blob<256>
template base_blob<256>::base_blob(const std::vector<unsigned char>&);
template std::string base_blob<256>::GetHex() const;
template std::string base_blob<256>::ToString() const;
template void base_blob<256>::SetHex(const char*);
template void base_blob<256>::SetHex(const std::string&);

const uint256 uint256::ZERO(0);
const uint256 uint256::ONE(1);

// End of File
