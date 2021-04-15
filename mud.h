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

#define MUD_CTRL_SIZE (CMSG_SPACE(MUD_PKTINFO_SIZE) + CMSG_SPACE(sizeof(in6_pktinfo)))

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

    void stat_update(stat*, const uint64_t val);

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
        state state;
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
        path_conf conf;
        path_status status;
        sockaddress remote;
        stat rtt;
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

    void path_update_mtu(path*, size_t);
    void path_update_rl(path*, uint64_t now, uint64_t tx_dt, uint64_t tx_bytes, uint64_t tx_pkt, uint64_t rx_dt, uint64_t rx_bytes, uint64_t rx_pkt);

    struct paths {
        path* path;
        unsigned count;
    };

    path* paths_get_path(paths*, path_conf, uint64_t now);
    int paths_set_path(paths*, path_conf, uint64_t now);

    struct error {
        sockaddress addr;
        uint64_t time;
        uint64_t count;
    };

    struct errors {
        error decrypt;
        error clocksync;
        error keyx;
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
        addr addr;
    };
    
    struct crypto_key {
        struct {
            unsigned char key[MUD_KEY_SIZE];
        } encrypt, decrypt;
        int aes;
    };

    int crypto_key_encrypt(const crypto_key* k, const unsigned char* src, unsigned char* dst, size_t size);
    int crypto_key_decrypt(const crypto_key* k, const unsigned char* src, unsigned char* dst, size_t size);

    struct crypto_keys {
        uint64_t time;
        unsigned char secret[crypto_scalarmult_SCALARBYTES];
        unsigned char remote[MUD_PUBKEY_SIZE];
        unsigned char local[MUD_PUBKEY_SIZE];
        crypto_key priv, last, next, current;
        int use_next;
        int aes;
    };

    int crypto_keys_init(crypto_keys*, uint64_t now, uint64_t timeout);
    int crypto_keys_exchange(crypto_keys*, unsigned char* remote_key, int aes);

    size_t crypto_keys_encrypt(crypto_keys*, uint64_t now, unsigned char* dst, size_t dst_size, const unsigned char* src, size_t src_size);
    size_t crypto_keys_decrypt(crypto_keys*, unsigned char* dst, size_t dst_size, const unsigned char* src, size_t src_size);

    struct mud {
        int fd;
        conf conf;
        paths paths;
        unsigned pref;
        crypto_keys keys;
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

    int mud_set_conf(mud*, conf*);

    int mud_update(mud*);
    int mud_send_wait(mud*);

    int mud_recv(mud*, void*, size_t);
    int mud_send(mud*, const void*, size_t);

    int mud_get_errors(mud*, errors*);
    int mud_get_fd(mud*);
    size_t mud_get_mtu(mud*);
}