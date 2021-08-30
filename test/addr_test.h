#include <cpptest-lite/cpptest.h>
#include "../mud.h"

class AddrTest : public Test::Suite {
public:
    AddrTest() {
        TEST_ADD(AddrTest::test_addr_from_sockaddress_v4);
        TEST_ADD(AddrTest::test_addr_from_sockaddress_v6);
    }
    
    void test_addr_from_sockaddress_v4() {
        mud::sockaddress sock = {
            .sin = {
                .sin_family = AF_INET,
                .sin_port = htons(2021),
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
            },
        };

        mud::addr addr = {};

        int err = mud::addr_from_sockaddress(&addr, &sock);

        TEST_ASSERT_EQUALS(0, err);
        TEST_ASSERT_EQUALS(INADDR_LOOPBACK, (addr.v4[0] << 24) | (addr.v4[1] << 16) | (addr.v4[2] << 8) | addr.v4[3]);
        TEST_ASSERT_EQUALS(2021, (addr.port[0] << 8) | addr.port[1]);
    }

    void test_addr_from_sockaddress_v6() {
        mud::sockaddress sock = {
            .sin6 = {
                .sin6_family = AF_INET6,
                .sin6_port = htons(2026),
                .sin6_addr = IN6ADDR_LOOPBACK_INIT,
            },
        };

        mud::addr addr = {};

        int err = mud::addr_from_sockaddress(&addr, &sock);

        TEST_ASSERT_EQUALS(0, err);
        TEST_ASSERT_EQUALS(1, addr.v6[15]);
        TEST_ASSERT_EQUALS(2026, (addr.port[0] << 8) | addr.port[1]);
    }
};

