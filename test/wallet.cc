// Copyright (c) 2022 Mark Friedenbach
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

#include <gtest/gtest.h>

#include "wallet.h"

TEST(amount, parase) {
    {
        Amount amt;
        EXPECT_TRUE(amt.parse("0.1"));
        EXPECT_EQ(amt.i64, 10000000);
    }
    {
        Amount amt;
        EXPECT_TRUE(amt.parse("\"0.1\""));
        EXPECT_EQ(amt.i64, 10000000);
    }
    {
        Amount amt;
        EXPECT_TRUE(amt.parse("0.00000001"));
        EXPECT_EQ(amt.i64, 1);
        EXPECT_FALSE(amt.parse("0.000000001"));
    }
    {
        Amount amt;
        EXPECT_TRUE(amt.parse("\"0.00000001\""));
        EXPECT_EQ(amt.i64, 1);
        EXPECT_FALSE(amt.parse("\"0.000000001\""));
    }
    {
        Amount amt;
        EXPECT_TRUE(amt.parse("30"));
        EXPECT_EQ(amt.i64, 3000000000);
    }
    {
        Amount amt;
        EXPECT_TRUE(amt.parse("\"30\""));
        EXPECT_EQ(amt.i64, 3000000000);
    }
    {
        Amount amt;
        EXPECT_TRUE(amt.parse("30.0"));
        EXPECT_EQ(amt.i64, 3000000000);
    }
    {
        Amount amt;
        EXPECT_TRUE(amt.parse("\"30.0\""));
        EXPECT_EQ(amt.i64, 3000000000);
        EXPECT_FALSE(amt.parse("\"\"30.0\""));
        EXPECT_FALSE(amt.parse("\"\"30.0\"\""));
        EXPECT_FALSE(amt.parse("\"\"30\".0\""));
    }
}

TEST(amount, to_string) {
    using std::to_string;
    EXPECT_EQ(to_string(Amount(3)), "0.00000003");
    EXPECT_EQ(to_string(Amount(30)), "0.0000003");
    EXPECT_EQ(to_string(Amount(300)), "0.000003");
    EXPECT_EQ(to_string(Amount(3000)), "0.00003");
    EXPECT_EQ(to_string(Amount(30000)), "0.0003");
    EXPECT_EQ(to_string(Amount(300000)), "0.003");
    EXPECT_EQ(to_string(Amount(3000000)), "0.03");
    EXPECT_EQ(to_string(Amount(30000000)), "0.3");
    EXPECT_EQ(to_string(Amount(300000000)), "3");
    EXPECT_EQ(to_string(Amount(3000000000)), "30");
    EXPECT_EQ(to_string(Amount(3000000300)), "30.000003");
}

// End of File
