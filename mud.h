#pragma once

#include <stddef.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sodium.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <net/if.h>

#if defined __APPLE__
#include <mach/mach_time.h>
#endif

#include "aegis256/aegis256.h"

#if !defined MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

#if defined __linux__
#define MUD_V4V6 1
#else
#define MUD_V4V6 0
#endif

#if defined IP_PKTINFO
#define MUD_PKTINFO IP_PKTINFO
#define MUD_PKTINFO_SRC(X) &((in_pktinfo *)(X))->ipi_addr
#define MUD_PKTINFO_DST(X) &((in_pktinfo *)(X))->ipi_spec_dst
#define MUD_PKTINFO_SIZE sizeof(in_pktinfo)
#elif defined IP_RECVDSTADDR
#define MUD_PKTINFO IP_RECVDSTADDR
#define MUD_PKTINFO_SRC(X) (X)
#define MUD_PKTINFO_DST(X) (X)
#define MUD_PKTINFO_SIZE sizeof(in_addr)
#endif

#if defined IP_MTU_DISCOVER
#define MUD_DFRAG IP_MTU_DISCOVER
#define MUD_DFRAG_OPT IP_PMTUDISC_PROBE
#elif defined IP_DONTFRAG
#define MUD_DFRAG IP_DONTFRAG
#define MUD_DFRAG_OPT 1
#endif

#define MUD_PATH_MAX    (32U)
#define MUD_PUBKEY_SIZE (32U)

#define MUD_ONE_MSEC (UINT64_C(1000))
#define MUD_ONE_SEC  (1000 * MUD_ONE_MSEC)
#define MUD_ONE_MIN  (60 * MUD_ONE_SEC)

#define MUD_TIME_SIZE    (6U)
#define MUD_TIME_BITS    (MUD_TIME_SIZE * 8U)
#define MUD_TIME_MASK(X) ((X) & ((UINT64_C(1) << MUD_TIME_BITS) - 2))

#define MUD_KEY_SIZE (32U)
#define MUD_MAC_SIZE (16U)

#define MUD_MSG(X)       ((X) & UINT64_C(1))
#define MUD_MSG_MARK(X)  ((X) | UINT64_C(1))
#define MUD_MSG_SENT_MAX (5)

#define MUD_PKT_MIN_SIZE (MUD_TIME_SIZE + MUD_MAC_SIZE)
#define MUD_PKT_MAX_SIZE (1500U)

#define MUD_MTU_MIN ( 576U + MUD_PKT_MIN_SIZE)
#define MUD_MTU_MAX (1450U + MUD_PKT_MIN_SIZE)

#define MUD_CTRL_SIZE (CMSG_SPACE(MUD_PKTINFO_SIZE) + \
                       CMSG_SPACE(sizeof(in6_pktinfo)))

#define MUD_STORE_MSG(D,S) mud_store((D),(S),sizeof(D))
#define MUD_LOAD_MSG(S)    mud_load((S),sizeof(S))

namespace mud {
    enum state {
        EMPTY = 0,
        DOWN,
        PASSIVE,
        UP,
        LAST,
    };

    enum path_status {
        DELETING = 0,
        PROBING,
        DEGRADED,
        LOSSY,
        WAITING,
        READY,
        RUNNING,
    };

    struct stat {
        uint64_t val;
        uint64_t var;
        int setup;
    };

    struct conf {
        uint64_t keepalive;
        uint64_t timetolerance;
        uint64_t kxtimeout;
    };

    union sockaddress {
        sockaddr sa;
        sockaddr_in sin;
        sockaddr_in6 sin6;
    };

    int sockaddress_localaddr(sockaddress*, msghdr*);
    int sockaddress_cmp_addr(sockaddress*, sockaddress*);
    int sockaddress_cmp_port(sockaddress*, sockaddress*);
    struct addr; // forward declaration
    void sockaddress_from_addr(sockaddress*, addr*);
    void sockaddress_unmapv4(sockaddress*);

    struct addr {
        union {
            unsigned char v6[16];
            struct {
                unsigned char zero[10];
                unsigned char ff[2];
                unsigned char v4[4];
            };
        };
        unsigned char port[2];
    };

    

    int addr_is_v6(addr*);
    int addr_from_sockaddress(addr*, sockaddress*);

    struct path_conf {
        enum state state;
        sockaddress local;
        sockaddress remote;
        uint64_t tx_max_rate;
        uint64_t rx_max_rate;
        uint64_t beat;
        unsigned char pref;
        unsigned char fixed_rate;
        unsigned char loss_limit;
    };

    struct path {
        struct path_conf conf;
        enum path_status status;
        sockaddress remote;
        struct stat rtt;
        struct {
            uint64_t total;
            uint64_t bytes;
            uint64_t time;
            uint64_t rate;
            uint64_t loss;
        } tx, rx;
        struct {
            struct {
                uint64_t total;
                uint64_t bytes;
                uint64_t time;
                uint64_t acc;
                uint64_t acc_time;
            } tx, rx;
            uint64_t time;
            uint64_t sent;
            uint64_t set;
        } msg;
        struct {
            size_t min;
            size_t max;
            size_t probe;
            size_t last;
            size_t ok;
        } mtu;
        uint64_t idle;
    };

    struct error {
        sockaddress addr;
        uint64_t time;
        uint64_t count;
    };

    struct errors {
        struct error decrypt;
        struct error clocksync;
        struct error keyx;
    };

    struct paths {
        struct path path[MUD_PATH_MAX];
        unsigned count;
    };

    struct crypto_opt {
        unsigned char* dst;
        const unsigned char* src;
        size_t size;
    };

    struct msg {
        unsigned char sent_time[MUD_TIME_SIZE];
        unsigned char aes;
        unsigned char pkey[MUD_PUBKEY_SIZE];
        struct {
            unsigned char bytes[sizeof(uint64_t)];
            unsigned char total[sizeof(uint64_t)];
        } tx, rx, fw;
        unsigned char max_rate[sizeof(uint64_t)];
        unsigned char beat[MUD_TIME_SIZE];
        unsigned char mtu[2];
        unsigned char pref;
        unsigned char loss;
        unsigned char fixed_rate;
        unsigned char loss_limit;
        struct addr addr;
    };

    struct crypto_key {
        struct {
            unsigned char key[MUD_KEY_SIZE];
        } encrypt, decrypt;
        int aes;
    };

    struct keyx_t {
        uint64_t time;
        unsigned char secret[crypto_scalarmult_SCALARBYTES];
        unsigned char remote[MUD_PUBKEY_SIZE];
        unsigned char local[MUD_PUBKEY_SIZE];
        crypto_key priv, last, next, current;
        int use_next;
        int aes;
    };

    struct mud {
        int fd;
        conf conf;
        path* paths;
        unsigned pref;
        unsigned capacity;
        keyx_t keyx;
        uint64_t last_recv_time;
        size_t mtu;
        errors err;
        uint64_t rate;
        uint64_t window;
        uint64_t window_time;
        uint64_t base_time;
    #if defined __APPLE__
        mach_timebase_info_data_t mtid;
    #endif
    };

    mud* mud_create (sockaddress*, unsigned char*, int*);
    void mud_delete (mud*);

    uint64_t mud_now(mud*);

    int mud_set(mud*, conf*);
    int mud_set_path(mud*, path_conf*);

    int mud_update(mud*);
    int mud_send_wait(mud*);

    int mud_recv(mud*, void*, size_t);
    int mud_send(mud*, const void*, size_t);

    int mud_get_errors(mud*, errors*);
    int mud_get_fd(mud*);
    size_t mud_get_mtu(mud*);
    int mud_get_paths(mud*, paths*, sockaddress *, sockaddress *);


}