#pragma once

#include <stddef.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <sodium.h>

#if defined __APPLE__
#include <mach/mach_time.h>
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

struct mud;

enum mud_state {
    MUD_EMPTY = 0,
    MUD_DOWN,
    MUD_PASSIVE,
    MUD_UP,
    MUD_LAST,
};

enum mud_path_status {
    MUD_DELETING = 0,
    MUD_PROBING,
    MUD_DEGRADED,
    MUD_LOSSY,
    MUD_WAITING,
    MUD_READY,
    MUD_RUNNING,
};

struct mud_stat {
    uint64_t val;
    uint64_t var;
    int setup;
};

struct mud_conf {
    uint64_t keepalive;
    uint64_t timetolerance;
    uint64_t kxtimeout;
};

union mud_sockaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

struct mud_path_conf {
    enum mud_state state;
    union mud_sockaddr local;
    union mud_sockaddr remote;
    uint64_t tx_max_rate;
    uint64_t rx_max_rate;
    uint64_t beat;
    unsigned char pref;
    unsigned char fixed_rate;
    unsigned char loss_limit;
};

struct mud_path {
    struct mud_path_conf conf;
    enum mud_path_status status;
    union mud_sockaddr remote;
    struct mud_stat rtt;
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

struct mud_error {
    union mud_sockaddr addr;
    uint64_t time;
    uint64_t count;
};

struct mud_errors {
    struct mud_error decrypt;
    struct mud_error clocksync;
    struct mud_error keyx;
};

struct mud_paths {
    struct mud_path path[MUD_PATH_MAX];
    unsigned count;
};

struct mud_crypto_opt {
    unsigned char* dst;
    const unsigned char* src;
    size_t size;
};

struct mud_addr {
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

struct mud_msg {
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
    struct mud_addr addr;
};

struct mud_crypto_key {
    struct {
        unsigned char key[MUD_KEY_SIZE];
    } encrypt, decrypt;
    int aes;
};

struct mud_keyx_t {
    uint64_t time;
    unsigned char secret[crypto_scalarmult_SCALARBYTES];
    unsigned char remote[MUD_PUBKEY_SIZE];
    unsigned char local[MUD_PUBKEY_SIZE];
    mud_crypto_key priv, last, next, current;
    int use_next;
    int aes;
};

struct mud {
    int fd;
    mud_conf conf;
    mud_path* paths;
    unsigned pref;
    unsigned capacity;
    mud_keyx_t keyx;
    uint64_t last_recv_time;
    size_t mtu;
    mud_errors err;
    uint64_t rate;
    uint64_t window;
    uint64_t window_time;
    uint64_t base_time;
#if defined __APPLE__
    mach_timebase_info_data_t mtid;
#endif
};

mud* mud_create (union mud_sockaddr*, unsigned char*, int*);
void mud_delete (mud*);

int mud_set(mud*, mud_conf*);
int mud_set_path(mud*, mud_path_conf*);

int mud_update(mud*);
int mud_send_wait(mud*);

int mud_recv(mud*, void*, size_t);
int mud_send(mud*, const void*, size_t);

int mud_get_errors(mud*, mud_errors*);
int mud_get_fd(mud*);
size_t mud_get_mtu(mud*);
int mud_get_paths(mud*, mud_paths*, union mud_sockaddr *, union mud_sockaddr *);
