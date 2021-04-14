#if defined __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#if defined __linux__ && !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "mud.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <net/if.h>

#include <sodium.h>
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

static int mud_send_msg(mud* m, mud_path* path, uint64_t now, uint64_t sent_time, uint64_t fw_bytes, uint64_t fw_total, size_t size);

static inline int mud_encrypt_opt(const mud_crypto_key* k, const mud_crypto_opt* c) {
    if (k->aes) {
        unsigned char npub[AEGIS256_NPUBBYTES] = {0};
        memcpy(npub, c->dst, MUD_TIME_SIZE);
        return aegis256_encrypt(
            c->dst + MUD_TIME_SIZE,
            NULL,
            c->src,
            c->size,
            c->dst,
            MUD_TIME_SIZE,
            npub,
            k->encrypt.key
        );
    } else {
        unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
        memcpy(npub, c->dst, MUD_TIME_SIZE);
        return crypto_aead_chacha20poly1305_encrypt(
            c->dst + MUD_TIME_SIZE,
            NULL,
            c->src,
            c->size,
            c->dst,
            MUD_TIME_SIZE,
            NULL,
            npub,
            k->encrypt.key
        );
    }
}

static inline int mud_decrypt_opt(const mud_crypto_key* k, const mud_crypto_opt* c) {
    if (k->aes) {
        unsigned char npub[AEGIS256_NPUBBYTES] = {0};
        memcpy(npub, c->src, MUD_TIME_SIZE);
        return aegis256_decrypt(
            c->dst,
            NULL,
            c->src + MUD_TIME_SIZE,
            c->size - MUD_TIME_SIZE,
            c->src, MUD_TIME_SIZE,
            npub,
            k->decrypt.key
        );
    } else {
        unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
        memcpy(npub, c->src, MUD_TIME_SIZE);
        return crypto_aead_chacha20poly1305_decrypt(
            c->dst,
            NULL,
            NULL,
            c->src + MUD_TIME_SIZE,
            c->size - MUD_TIME_SIZE,
            c->src, MUD_TIME_SIZE,
            npub,
            k->decrypt.key
        );
    }
}

static inline void mud_store(unsigned char* dst, uint64_t src, size_t size) {
    dst[0] = (unsigned char)(src);
    dst[1] = (unsigned char)(src >> 8);
    if (size <= 2) return;
    dst[2] = (unsigned char)(src >> 16);
    dst[3] = (unsigned char)(src >> 24);
    dst[4] = (unsigned char)(src >> 32);
    dst[5] = (unsigned char)(src >> 40);
    if (size <= 6) return;
    dst[6] = (unsigned char)(src >> 48);
    dst[7] = (unsigned char)(src >> 56);
}

static inline uint64_t mud_load(const unsigned char* src, size_t size) {
    uint64_t ret = 0;
    ret = src[0];
    ret |= ((uint64_t)src[1]) << 8;
    if (size <= 2) return ret;
    ret |= ((uint64_t)src[2]) << 16;
    ret |= ((uint64_t)src[3]) << 24;
    ret |= ((uint64_t)src[4]) << 32;
    ret |= ((uint64_t)src[5]) << 40;
    if (size <= 6) return ret;
    ret |= ((uint64_t)src[6]) << 48;
    ret |= ((uint64_t)src[7]) << 56;
    return ret;
}

static int mud_sso_int(int fd, int level, int optname, int opt) {
    return setsockopt(fd, level, optname, &opt, sizeof(opt));
}

static inline int mud_cmp_addr(union mud_sockaddr* a, union mud_sockaddr* b) {
    if (a->sa.sa_family != b->sa.sa_family)
        return 1;

    if (a->sa.sa_family == AF_INET)
        return memcmp(&a->sin.sin_addr, &b->sin.sin_addr,
                      sizeof(a->sin.sin_addr));

    if (a->sa.sa_family == AF_INET6)
        return memcmp(&a->sin6.sin6_addr, &b->sin6.sin6_addr,
                      sizeof(a->sin6.sin6_addr));
    return 1;
}

static inline int mud_cmp_port(union mud_sockaddr* a, union mud_sockaddr* b) {
    if (a->sa.sa_family != b->sa.sa_family)
        return 1;

    if (a->sa.sa_family == AF_INET)
        return memcmp(&a->sin.sin_port, &b->sin.sin_port,
                      sizeof(a->sin.sin_port));

    if (a->sa.sa_family == AF_INET6)
        return memcmp(&a->sin6.sin6_port, &b->sin6.sin6_port,
                      sizeof(a->sin6.sin6_port));
    return 1;
}

static void mud_hash_key(unsigned char* dst, unsigned char* key, unsigned char* secret, unsigned char* pk0, unsigned char* pk1) {
    crypto_generichash_state state;

    crypto_generichash_init(&state, key, MUD_KEY_SIZE, MUD_KEY_SIZE);
    crypto_generichash_update(&state, secret, crypto_scalarmult_BYTES);
    crypto_generichash_update(&state, pk0, MUD_PUBKEY_SIZE);
    crypto_generichash_update(&state, pk1, MUD_PUBKEY_SIZE);
    crypto_generichash_final(&state, dst, MUD_KEY_SIZE);

    sodium_memzero(&state, sizeof(state));
}

static inline uint64_t mud_time(void) {
#if defined CLOCK_REALTIME
    timespec tv;
    clock_gettime(CLOCK_REALTIME, &tv);
    return MUD_TIME_MASK(0
            + (uint64_t)tv.tv_sec * MUD_ONE_SEC
            + (uint64_t)tv.tv_nsec / MUD_ONE_MSEC);
#else
    timeval tv;
    gettimeofday(&tv, NULL);
    return MUD_TIME_MASK(0
            + (uint64_t)tv.tv_sec * MUD_ONE_SEC
            + (uint64_t)tv.tv_usec);
#endif
}



static inline uint64_t mud_abs_diff(uint64_t a, uint64_t b) {
    return (a >= b) ? a - b : b - a;
}

static inline int mud_timeout(uint64_t now, uint64_t last, uint64_t timeout) {
    return (!last) || (MUD_TIME_MASK(now - last) >= timeout);
}

static inline void mud_unmapv4(union mud_sockaddr* addr) {
    if (addr->sa.sa_family != AF_INET6)
        return;

    if (!IN6_IS_ADDR_V4MAPPED(&addr->sin6.sin6_addr))
        return;

    sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = addr->sin6.sin6_port,
    };
    memcpy(&sin.sin_addr.s_addr,
           &addr->sin6.sin6_addr.s6_addr[12],
           sizeof(sin.sin_addr.s_addr));

    addr->sin = sin;
}

static inline uint64_t mud_now(mud* m) {
#if defined __APPLE__
    return MUD_TIME_MASK(m->base_time
            + (mach_absolute_time() * m->mtid.numer / m->mtid.denom)
            / 1000ULL);
#elif defined CLOCK_MONOTONIC
    timespec tv;
    clock_gettime(CLOCK_MONOTONIC, &tv);
    return MUD_TIME_MASK(mud->base_time
            + (uint64_t)tv.tv_sec * MUD_ONE_SEC
            + (uint64_t)tv.tv_nsec / MUD_ONE_MSEC);
#else
    return mud_time();
#endif
}

static mud_path* mud_select_path(mud* m, uint16_t cursor) {
    uint64_t k = (cursor * m->rate) >> 16;

    for (unsigned i = 0; i < m->capacity; i++) {
        mud_path* path = &m->paths[i];

        if (path->status != MUD_RUNNING)
            continue;

        if (k < path->tx.rate)
            return path;

        k -= path->tx.rate;
    }
    return NULL;
}

int mud_get_paths(mud* m, mud_paths *paths, union mud_sockaddr* local, union mud_sockaddr* remote) {
    if (!paths) {
        errno = EINVAL;
        return -1;
    }
    unsigned count = 0;

    for (unsigned i = 0; i < m->capacity; i++) {
        mud_path* path = &m->paths[i];

        if (local && local->sa.sa_family &&
            mud_cmp_addr(local, &path->conf.local))
            continue;

        if (remote && remote->sa.sa_family &&
            (mud_cmp_addr(remote, &path->conf.remote) ||
             mud_cmp_port(remote, &path->conf.remote)))
            continue;

        if (path->conf.state != MUD_EMPTY)
            paths->path[count++] = *path;
    }
    paths->count = count;
    return 0;
}

static mud_path* mud_get_path(mud* m, union mud_sockaddr* local, union mud_sockaddr* remote, enum mud_state state) {
    if (local->sa.sa_family != remote->sa.sa_family) {
        errno = EINVAL;
        return NULL;
    }
    for (unsigned i = 0; i < m->capacity; i++) {
        mud_path* path = &m->paths[i];

        if (path->conf.state == MUD_EMPTY)
            continue;

        if (mud_cmp_addr(local, &path->conf.local)   ||
            mud_cmp_addr(remote, &path->conf.remote) ||
            mud_cmp_port(remote, &path->conf.remote))
            continue;

        return path;
    }
    if (state <= MUD_DOWN) {
        errno = 0;
        return NULL;
    }
    mud_path* path = NULL;

    for (unsigned i = 0; i < m->capacity; i++) {
        if (m->paths[i].conf.state == MUD_EMPTY) {
            path = &m->paths[i];
            break;
        }
    }
    if (!path) {
        if (m->capacity == MUD_PATH_MAX) {
            errno = ENOMEM;
            return NULL;
        }
        mud_path* paths = (mud_path*)realloc(m->paths,
                (m->capacity + 1) * sizeof(mud_path));

        if (!paths)
            return NULL;

        path = &paths[m->capacity];

        m->capacity++;
        m->paths = paths;
    }
    memset(path, 0, sizeof(mud_path));

    path->conf.local      = *local;
    path->conf.remote     = *remote;
    path->conf.state      = state;
    path->conf.beat       = 100 * MUD_ONE_MSEC;
    path->conf.fixed_rate = 1;
    path->conf.loss_limit = 255;
    path->status          = MUD_PROBING;
    path->idle            = mud_now(m);

    return path;
}


int mud_get_errors(mud* m, mud_errors* err) {
    if (!err) {
        errno = EINVAL;
        return -1;
    }
    memcpy(err, &m->err, sizeof(mud_errors));
    return 0;
}

int mud_set(mud* m, mud_conf *conf) {
    mud_conf c = m->conf;

    if (conf->keepalive)     c.keepalive     = conf->keepalive;
    if (conf->timetolerance) c.timetolerance = conf->timetolerance;
    if (conf->kxtimeout)     c.kxtimeout     = conf->kxtimeout;

    *conf = m->conf = c;
    return 0;
}

size_t mud_get_mtu(mud* m) {
    if (!m->mtu)
        return 0;

    return m->mtu - MUD_PKT_MIN_SIZE;
}

static int mud_setup_socket(int fd, int v4, int v6) {
    if ((mud_sso_int(fd, SOL_SOCKET, SO_REUSEADDR, 1)) ||
        (v4 && mud_sso_int(fd, IPPROTO_IP, MUD_PKTINFO, 1)) ||
        (v6 && mud_sso_int(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, 1)) ||
        (v6 && mud_sso_int(fd, IPPROTO_IPV6, IPV6_V6ONLY, !v4)))
        return -1;

#if defined MUD_DFRAG
    if (v4)
        mud_sso_int(fd, IPPROTO_IP, MUD_DFRAG, MUD_DFRAG_OPT);
#endif
    return 0;
}

static int mud_keyx(mud_keyx_t* kx, unsigned char* remote, int aes) {
    unsigned char secret[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(secret, kx->secret, remote))
        return 1;

    mud_hash_key(kx->next.encrypt.key,
                 kx->priv.encrypt.key,
                 secret, remote, kx->local);

    mud_hash_key(kx->next.decrypt.key,
                 kx->priv.encrypt.key,
                 secret, kx->local, remote);

    sodium_memzero(secret, sizeof(secret));

    memcpy(kx->remote, remote, MUD_PUBKEY_SIZE);
    kx->next.aes = kx->aes && aes;

    return 0;
}

static int mud_keyx_init(mud* m, uint64_t now) {
    mud_keyx_t *kx = &m->keyx;

    if (!mud_timeout(now, kx->time, m->conf.kxtimeout))
        return 1;

    static const unsigned char test[crypto_scalarmult_BYTES] = {
        0x9b, 0xf4, 0x14, 0x90, 0x0f, 0xef, 0xf8, 0x2d, 0x11, 0x32, 0x6e,
        0x3d, 0x99, 0xce, 0x96, 0xb9, 0x4f, 0x79, 0x31, 0x01, 0xab, 0xaf,
        0xe3, 0x03, 0x59, 0x1a, 0xcd, 0xdd, 0xb0, 0xfb, 0xe3, 0x49
    };
    unsigned char tmp[crypto_scalarmult_BYTES];

    do {
        randombytes_buf(kx->secret, sizeof(kx->secret));
        crypto_scalarmult_base(kx->local, kx->secret);
    } while (crypto_scalarmult(tmp, test, kx->local));

    sodium_memzero(tmp, sizeof(tmp));
    kx->time = now;

    return 0;
}

mud* mud_create(union mud_sockaddr* addr, unsigned char* key, int* aes) {
    if (!addr || !key || !aes)
        return NULL;

    int v4, v6;
    socklen_t addrlen = 0;

    switch (addr->sa.sa_family) {
    case AF_INET:
        addrlen = sizeof(sockaddr_in);
        v4 = 1;
        v6 = 0;
        break;
    case AF_INET6:
        addrlen = sizeof(sockaddr_in6);
        v4 = MUD_V4V6;
        v6 = 1;
        break;
    default:
        return NULL;
    }
    if (sodium_init() == -1)
        return NULL;

    mud* m = (mud*)sodium_malloc(sizeof(mud));

    if (!m)
        return NULL;

    memset(m, 0, sizeof(mud));
    m->fd = socket(addr->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);

    if ((m->fd == -1) ||
        (mud_setup_socket(m->fd, v4, v6)) ||
        (bind(m->fd, &addr->sa, addrlen)) ||
        (getsockname(m->fd, &addr->sa, &addrlen))) {
        mud_delete(m);
        return NULL;
    }
    m->conf.keepalive     = 25 * MUD_ONE_SEC;
    m->conf.timetolerance = 10 * MUD_ONE_MIN;
    m->conf.kxtimeout     = 60 * MUD_ONE_MIN;

#if defined __APPLE__
    mach_timebase_info(&m->mtid);
#endif

    uint64_t now = mud_now(m);
    uint64_t base_time = mud_time();

    if (base_time > now)
        m->base_time = base_time - now;

    memcpy(m->keyx.priv.encrypt.key, key, MUD_KEY_SIZE);
    memcpy(m->keyx.priv.decrypt.key, key, MUD_KEY_SIZE);
    sodium_memzero(key, MUD_KEY_SIZE);

    m->keyx.current = m->keyx.priv;
    m->keyx.next = m->keyx.priv;
    m->keyx.last = m->keyx.priv;

    if (*aes && !aegis256_is_available())
        *aes = 0;

    m->keyx.aes = *aes;
    return m;
}

int mud_get_fd(mud* m) {
    if (!m)
        return -1;

    return m->fd;
}

void mud_delete(mud* m) {
    if (!m)
        return;

    if (m->paths)
        free(m->paths);

    if (m->fd >= 0)
        close(m->fd);

    sodium_free(m);
}

static size_t mud_encrypt(mud* m, uint64_t now, unsigned char* dst, size_t dst_size, const unsigned char* src, size_t src_size) {
    const size_t size = src_size + MUD_PKT_MIN_SIZE;

    if (size > dst_size)
        return 0;

    const mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };

    mud_store(dst, now, MUD_TIME_SIZE);

    if (m->keyx.use_next) {
        mud_encrypt_opt(&m->keyx.next, &opt);
    } else {
        mud_encrypt_opt(&m->keyx.current, &opt);
    }
    return size;
}

static size_t mud_decrypt(mud* m, unsigned char* dst, size_t dst_size, const unsigned char* src, size_t src_size) {
    const size_t size = src_size - MUD_PKT_MIN_SIZE;

    if (size > dst_size)
        return 0;

    const mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };
    if (mud_decrypt_opt(&m->keyx.current, &opt)) {
        if (!mud_decrypt_opt(&m->keyx.next, &opt)) {
            m->keyx.last = m->keyx.current;
            m->keyx.current = m->keyx.next;
            m->keyx.use_next = 0;
        } else {
            if (mud_decrypt_opt(&m->keyx.last, &opt) &&
                mud_decrypt_opt(&m->keyx.priv, &opt))
                return 0;
        }
    }
    return size;
}

static size_t mud_decrypt_msg(mud* m, unsigned char* dst, size_t dst_size, const unsigned char* src, size_t src_size) {
    const size_t size = src_size - MUD_PKT_MIN_SIZE;

    if (size < sizeof(mud_msg) || size > dst_size)
        return 0;

    const mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };

    if (mud_decrypt_opt(&m->keyx.priv, &opt))
        return 0;

    return size;
}

static int mud_localaddr(union mud_sockaddr* addr, msghdr *msg) {
    cmsghdr *cmsg = CMSG_FIRSTHDR(msg);

    for (; cmsg; cmsg = CMSG_NXTHDR(msg, cmsg)) {
        if ((cmsg->cmsg_level == IPPROTO_IP) &&
            (cmsg->cmsg_type == MUD_PKTINFO)) {
            addr->sa.sa_family = AF_INET;
            memcpy(&addr->sin.sin_addr,
                   MUD_PKTINFO_SRC(CMSG_DATA(cmsg)),
                   sizeof(in_addr));
            return 0;
        }
        if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
            (cmsg->cmsg_type == IPV6_PKTINFO)) {
            addr->sa.sa_family = AF_INET6;
            memcpy(&addr->sin6.sin6_addr,
                   &((in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
                   sizeof(in6_addr));
            mud_unmapv4(addr);
            return 0;
        }
    }
    return 1;
}

static int mud_addr_is_v6(mud_addr* addr) {
    static const unsigned char v4mapped[] = {
        [10] = 255,
        [11] = 255,
    };
    return memcmp(addr->v6, v4mapped, sizeof(v4mapped));
}

static int mud_addr_from_sock(mud_addr* addr, union mud_sockaddr* sock) {
    if (sock->sa.sa_family == AF_INET) {
        memset(addr->zero, 0, sizeof(addr->zero));
        memset(addr->ff, 0xFF, sizeof(addr->ff));
        memcpy(addr->v4, &sock->sin.sin_addr, 4);
        memcpy(addr->port, &sock->sin.sin_port, 2);
    } else if (sock->sa.sa_family == AF_INET6) {
        memcpy(addr->v6, &sock->sin6.sin6_addr, 16);
        memcpy(addr->port, &sock->sin6.sin6_port, 2);
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }
    return 0;
}

static void mud_sock_from_addr(union mud_sockaddr* sock, mud_addr* addr) {
    if (mud_addr_is_v6(addr)) {
        sock->sin6.sin6_family = AF_INET6;
        memcpy(&sock->sin6.sin6_addr, addr->v6, 16);
        memcpy(&sock->sin6.sin6_port, addr->port, 2);
    } else {
        sock->sin.sin_family = AF_INET;
        memcpy(&sock->sin.sin_addr, addr->v4, 4);
        memcpy(&sock->sin.sin_port, addr->port, 2);
    }
}

static void mud_update_rl(mud* m, mud_path* path, uint64_t now, uint64_t tx_dt, uint64_t tx_bytes, uint64_t tx_pkt, uint64_t rx_dt, uint64_t rx_bytes, uint64_t rx_pkt) {
    if (rx_dt && rx_dt > tx_dt + (tx_dt >> 3)) {
        if (!path->conf.fixed_rate)
            path->tx.rate = (7 * rx_bytes * MUD_ONE_SEC) / (8 * rx_dt);
    } else {
        uint64_t tx_acc = path->msg.tx.acc + tx_pkt;
        uint64_t rx_acc = path->msg.rx.acc + rx_pkt;

        if (tx_acc > 1000) {
            if (tx_acc >= rx_acc)
                path->tx.loss = (tx_acc - rx_acc) * 255U / tx_acc;
            path->msg.tx.acc = tx_acc - (tx_acc >> 4);
            path->msg.rx.acc = rx_acc - (rx_acc >> 4);
        } else {
            path->msg.tx.acc = tx_acc;
            path->msg.rx.acc = rx_acc;
        }

        if (!path->conf.fixed_rate)
            path->tx.rate += path->tx.rate / 10;
    }
    if (path->tx.rate > path->conf.tx_max_rate)
        path->tx.rate = path->conf.tx_max_rate;
}

static void mud_update_mtu(mud_path* path, size_t size) {
    if (!path->mtu.probe) {
        if (!path->mtu.last) {
            path->mtu.min = MUD_MTU_MIN;
            path->mtu.max = MUD_MTU_MAX;
            path->mtu.probe = MUD_MTU_MAX;
        }
        return;
    }
    if (size) {
        if (path->mtu.min > size || path->mtu.max < size)
            return;
        path->mtu.min = size + 1;
        path->mtu.last = size;
    } else {
        path->mtu.max = path->mtu.probe - 1;
    }

    size_t probe = (path->mtu.min + path->mtu.max) >> 1;

    if (path->mtu.min > path->mtu.max) {
        path->mtu.probe = 0;
    } else {
        path->mtu.probe = probe;
    }
}

static void mud_update_stat(mud_stat *stat, const uint64_t val) {
    if (stat->setup) {
        const uint64_t var = mud_abs_diff(stat->val, val);
        stat->var = ((stat->var << 1) + stat->var + var) >> 2;
        stat->val = ((stat->val << 3) - stat->val + val) >> 3;
    } else {
        stat->setup = 1;
        stat->var = val >> 1;
        stat->val = val;
    }
}

static int mud_path_update(mud* m, mud_path* path, uint64_t now) {
    switch (path->conf.state) {
    case MUD_DOWN:
        path->status = MUD_DELETING;
        if (mud_timeout(now, path->rx.time, 2 * MUD_ONE_MIN))
            memset(path, 0, sizeof(mud_path));
        return 0;
    case MUD_PASSIVE:
        if (mud_timeout(now, m->last_recv_time, 2 * MUD_ONE_MIN)) {
            memset(path, 0, sizeof(mud_path));
            return 0;
        }
    case MUD_UP: break;
    default:     return 0;
    }
    if (path->msg.sent >= MUD_MSG_SENT_MAX) {
        if (path->mtu.probe) {
            mud_update_mtu(path, 0);
            path->msg.sent = 0;
        } else {
            path->msg.sent = MUD_MSG_SENT_MAX;
            path->status = MUD_DEGRADED;
            return 0;
        }
    }
    if (!path->mtu.ok) {
        path->status = MUD_PROBING;
        return 0;
    }
    if (path->tx.loss > path->conf.loss_limit ||
        path->rx.loss > path->conf.loss_limit) {
        path->status = MUD_LOSSY;
        return 0;
    }
    if (path->conf.state == MUD_PASSIVE &&
        mud_timeout(m->last_recv_time, path->rx.time,
                    MUD_MSG_SENT_MAX * path->conf.beat)) {
        path->status = MUD_WAITING;
        return 0;
    }
    if (path->conf.pref > m->pref) {
        path->status = MUD_READY;
    } else if (path->status != MUD_RUNNING) {
        path->status = MUD_RUNNING;
        path->idle = now;
    }
    return 1;
}

static uint64_t mud_path_track(mud* m, mud_path* path, uint64_t now) {
    if (path->conf.state != MUD_UP)
        return now;

    uint64_t timeout = path->conf.beat;

    switch (path->status) {
        case MUD_RUNNING:
            if (mud_timeout(now, path->idle, MUD_ONE_SEC))
                timeout = m->conf.keepalive;
            break;
        case MUD_DEGRADED:
        case MUD_LOSSY:
        case MUD_PROBING:
            break;
        default:
            return now;
    }
    if (mud_timeout(now, path->msg.time, timeout)) {
        path->msg.sent++;
        path->msg.time = now;
        mud_send_msg(m, path, now, 0, 0, 0, path->mtu.probe);
        now = mud_now(m);
    }
    return now;
}

static void mud_update_window(mud* m, const uint64_t now) {
    uint64_t elapsed = MUD_TIME_MASK(now - m->window_time);

    if (elapsed > MUD_ONE_MSEC) {
        m->window += m->rate * elapsed / MUD_ONE_SEC;
        m->window_time = now;
    }
    uint64_t window_max = m->rate * 100 * MUD_ONE_MSEC / MUD_ONE_SEC;

    if (m->window > window_max)
        m->window = window_max;
}

int mud_update(mud* m) {
    unsigned count = 0;
    unsigned pref = 255;
    unsigned next_pref = 255;
    uint64_t rate = 0;
    size_t   mtu = 0;
    uint64_t now = mud_now(m);

    if (!mud_keyx_init(m, now))
        now = mud_now(m);

    for (unsigned i = 0; i < m->capacity; i++) {
        mud_path* path = &m->paths[i];

        if (mud_path_update(m, path, now)) {
            if (next_pref > path->conf.pref && path->conf.pref > m->pref)
                next_pref = path->conf.pref;
            if (pref > path->conf.pref)
                pref = path->conf.pref;
            if (path->status == MUD_RUNNING)
                rate += path->tx.rate;
        }
        if (path->mtu.ok) {
            if (!mtu || mtu > path->mtu.ok)
                mtu = path->mtu.ok;
        }
        now = mud_path_track(m, path, now);
        count++;
    }
    if (rate) {
        m->pref = pref;
    } else {
        m->pref = next_pref;

        for (unsigned i = 0; i < m->capacity; i++) {
            mud_path* path = &m->paths[i];

            if (!mud_path_update(m, path, now))
                continue;

            if (path->status == MUD_RUNNING)
                rate += path->tx.rate;
        }
    }
    m->rate = rate;
    m->mtu = mtu;

    mud_update_window(m, now);

    if (!count)
        return -1;

    return m->window < 1500;
}

int mud_set_path(mud* m, mud_path_conf *conf) {
    if (conf->state < MUD_EMPTY || conf->state >= MUD_LAST) {
        errno = EINVAL;
        return -1;
    }
    mud_path* path = mud_get_path(m, &conf->local,
                                              &conf->remote,
                                              conf->state);
    if (!path)
        return -1;

    mud_path_conf c = path->conf;

    if (conf->state)       c.state       = conf->state;
    if (conf->pref)        c.pref        = conf->pref >> 1;
    if (conf->beat)        c.beat        = conf->beat * MUD_ONE_MSEC;
    if (conf->fixed_rate)  c.fixed_rate  = conf->fixed_rate >> 1;
    if (conf->loss_limit)  c.loss_limit  = conf->loss_limit;
    if (conf->tx_max_rate) c.tx_max_rate = path->tx.rate = conf->tx_max_rate;
    if (conf->rx_max_rate) c.rx_max_rate = path->rx.rate = conf->rx_max_rate;

    *conf = path->conf = c;
    return 0;
}

static int mud_send_path(mud* m, mud_path* path, uint64_t now, void *data, size_t size, int flags) {
    if (!size || !path)
        return 0;

    unsigned char ctrl[MUD_CTRL_SIZE];
    memset(ctrl, 0, sizeof(ctrl));

    iovec iov = {
        .iov_base = data,
        .iov_len = size,
    };

    msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = ctrl,
    };
    
    if (path->conf.remote.sa.sa_family == AF_INET) {
        msg.msg_name = &path->conf.remote.sin;
        msg.msg_namelen = sizeof(sockaddr_in);
        msg.msg_controllen = CMSG_SPACE(MUD_PKTINFO_SIZE);

        cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_IP;
        cmsg->cmsg_type = MUD_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(MUD_PKTINFO_SIZE);
        memcpy(MUD_PKTINFO_DST(CMSG_DATA(cmsg)),
               &path->conf.local.sin.sin_addr,
               sizeof(in_addr));
    } else if (path->conf.remote.sa.sa_family == AF_INET6) {
        msg.msg_name = &path->conf.remote.sin6;
        msg.msg_namelen = sizeof(sockaddr_in6);
        msg.msg_controllen = CMSG_SPACE(sizeof(in6_pktinfo));

        cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = IPPROTO_IPV6;
        cmsg->cmsg_type = IPV6_PKTINFO;
        cmsg->cmsg_len = CMSG_LEN(sizeof(in6_pktinfo));
        memcpy(&((in6_pktinfo *)CMSG_DATA(cmsg))->ipi6_addr,
               &path->conf.local.sin6.sin6_addr,
               sizeof(in6_addr));
    } else {
        errno = EAFNOSUPPORT;
        return -1;
    }
    ssize_t ret = sendmsg(m->fd, &msg, flags);

    path->tx.total++;
    path->tx.bytes += size;
    path->tx.time = now;

    if (m->window > size) {
        m->window -= size;
    } else {
        m->window = 0;
    }
    return (int)ret;
}

static int mud_send_msg(mud* m, mud_path* path, uint64_t now, uint64_t sent_time, uint64_t fw_bytes, uint64_t fw_total, size_t size) {
    unsigned char dst[MUD_PKT_MAX_SIZE];
    unsigned char src[MUD_PKT_MAX_SIZE] = {0};
    mud_msg *msg = (mud_msg *)src;

    if (size < MUD_PKT_MIN_SIZE + sizeof(mud_msg))
        size = MUD_PKT_MIN_SIZE + sizeof(mud_msg);

    mud_store(dst, MUD_MSG_MARK(now), MUD_TIME_SIZE);
    MUD_STORE_MSG(msg->sent_time, sent_time);

    if (mud_addr_from_sock(&msg->addr, &path->conf.remote))
        return -1;

    memcpy(msg->pkey, m->keyx.local, sizeof(m->keyx.local));
    msg->aes = (unsigned char)m->keyx.aes;

    if (!path->mtu.probe)
        MUD_STORE_MSG(msg->mtu, path->mtu.last);

    MUD_STORE_MSG(msg->tx.bytes, path->tx.bytes);
    MUD_STORE_MSG(msg->rx.bytes, path->rx.bytes);
    MUD_STORE_MSG(msg->tx.total, path->tx.total);
    MUD_STORE_MSG(msg->rx.total, path->rx.total);
    MUD_STORE_MSG(msg->fw.bytes, fw_bytes);
    MUD_STORE_MSG(msg->fw.total, fw_total);
    MUD_STORE_MSG(msg->max_rate, path->conf.rx_max_rate);
    MUD_STORE_MSG(msg->beat, path->conf.beat);

    msg->loss = (unsigned char)path->tx.loss;
    msg->pref = path->conf.pref;
    msg->fixed_rate = path->conf.fixed_rate;
    msg->loss_limit = path->conf.loss_limit;

    const mud_crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = size - MUD_PKT_MIN_SIZE,
    };
    mud_encrypt_opt(&m->keyx.priv, &opt);

    return mud_send_path(m, path, now, dst, size, sent_time ? MSG_CONFIRM : 0);
}

int mud_send(mud* m, const void* plain_data, size_t plain_size) {
    if (!plain_size)
        return 0;

    if (m->window < 1500) {
        errno = EAGAIN;
        return -1;
    }

    const uint64_t now = mud_now(m);
    unsigned char encrypted_data[MUD_PKT_MAX_SIZE];
    const size_t encrypted_size = mud_encrypt(m, now, encrypted_data, sizeof(encrypted_data), (const unsigned char*)plain_data, plain_size);

    if (!encrypted_size) {
        errno = EMSGSIZE;
        return -1;
    }

    uint16_t k;
    memcpy(&k, &encrypted_data[encrypted_size - sizeof(k)], sizeof(k));

    mud_path* path = mud_select_path(m, k);

    if (!path) {
        errno = EAGAIN;
        return -1;
    }
    path->idle = now;

    return mud_send_path(m, path, now, encrypted_data, encrypted_size, 0);
}

int mud_send_wait(mud* m) {
    return m->window < 1500;
}

static void mud_recv_msg(mud* m, mud_path* path, uint64_t now, uint64_t sent_time, unsigned char* data, size_t size) {
    mud_msg *msg = (mud_msg *)data;
    const uint64_t tx_time = MUD_LOAD_MSG(msg->sent_time);

    mud_sock_from_addr(&path->remote, &msg->addr);

    if (tx_time) {
        mud_update_stat(&path->rtt, MUD_TIME_MASK(now - tx_time));

        const uint64_t tx_bytes = MUD_LOAD_MSG(msg->fw.bytes);
        const uint64_t tx_total = MUD_LOAD_MSG(msg->fw.total);
        const uint64_t rx_bytes = MUD_LOAD_MSG(msg->rx.bytes);
        const uint64_t rx_total = MUD_LOAD_MSG(msg->rx.total);
        const uint64_t rx_time  = sent_time;

        if ((tx_time > path->msg.tx.time) && (tx_bytes > path->msg.tx.bytes) &&
            (rx_time > path->msg.rx.time) && (rx_bytes > path->msg.rx.bytes)) {
            if (path->msg.set && path->status > MUD_PROBING) {
                mud_update_rl(m, path, now,
                        MUD_TIME_MASK(tx_time - path->msg.tx.time),
                        tx_bytes - path->msg.tx.bytes,
                        tx_total - path->msg.tx.total,
                        MUD_TIME_MASK(rx_time - path->msg.rx.time),
                        rx_bytes - path->msg.rx.bytes,
                        rx_total - path->msg.rx.total);
            }
            path->msg.tx.time = tx_time;
            path->msg.rx.time = rx_time;
            path->msg.tx.bytes = tx_bytes;
            path->msg.rx.bytes = rx_bytes;
            path->msg.tx.total = tx_total;
            path->msg.rx.total = rx_total;
            path->msg.set = 1;
        }
        path->rx.loss = (uint64_t)msg->loss;
        path->msg.sent = 0;

        if (path->conf.state == MUD_PASSIVE)
            return;

        mud_update_mtu(path, size);

        if (path->mtu.last && path->mtu.last == MUD_LOAD_MSG(msg->mtu))
            path->mtu.ok = path->mtu.last;
    } else {
        path->conf.beat = MUD_LOAD_MSG(msg->beat);

        const uint64_t max_rate = MUD_LOAD_MSG(msg->max_rate);

        if (path->conf.tx_max_rate != max_rate || msg->fixed_rate)
            path->tx.rate = max_rate;

        path->conf.tx_max_rate = max_rate;
        path->conf.pref = msg->pref;
        path->conf.fixed_rate = msg->fixed_rate;
        path->conf.loss_limit = msg->loss_limit;

        path->mtu.last = MUD_LOAD_MSG(msg->mtu);
        path->mtu.ok = path->mtu.last;

        path->msg.sent++;
        path->msg.time = now;
    }
    if (memcmp(msg->pkey, m->keyx.remote, MUD_PUBKEY_SIZE)) {
        if (mud_keyx(&m->keyx, msg->pkey, msg->aes)) {
            m->err.keyx.addr = path->conf.remote;
            m->err.keyx.time = now;
            m->err.keyx.count++;
            return;
        }
    } else if (path->conf.state == MUD_UP) {
        m->keyx.use_next = 1;
    }
    mud_send_msg(m, path, now, sent_time,
                 MUD_LOAD_MSG(msg->tx.bytes),
                 MUD_LOAD_MSG(msg->tx.total),
                 size);
}

int mud_recv(mud* m, void *data, size_t size) {
    union mud_sockaddr remote;
    unsigned char ctrl[MUD_CTRL_SIZE];
    unsigned char packet[MUD_PKT_MAX_SIZE];

    iovec iov = {
        .iov_base = packet,
        .iov_len = sizeof(packet),
    };

    msghdr msg = {
        .msg_name = &remote,
        .msg_namelen = sizeof(remote),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = ctrl,
        .msg_controllen = sizeof(ctrl),
    };
    const ssize_t packet_size = recvmsg(m->fd, &msg, 0);

    if (packet_size == (ssize_t)-1)
        return -1;

    if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        (packet_size <= (ssize_t)MUD_PKT_MIN_SIZE))
        return 0;

    const uint64_t now = mud_now(m);
    const uint64_t sent_time = mud_load(packet, MUD_TIME_SIZE);

    mud_unmapv4(&remote);

    if ((MUD_TIME_MASK(now - sent_time) > m->conf.timetolerance) &&
        (MUD_TIME_MASK(sent_time - now) > m->conf.timetolerance)) {
        m->err.clocksync.addr = remote;
        m->err.clocksync.time = now;
        m->err.clocksync.count++;
        return 0;
    }
    const size_t ret = MUD_MSG(sent_time)
                     ? mud_decrypt_msg(m, (unsigned char*)data, size, packet, (size_t)packet_size)
                     : mud_decrypt(m, (unsigned char*)data, size, packet, (size_t)packet_size);
    if (!ret) {
        m->err.decrypt.addr = remote;
        m->err.decrypt.time = now;
        m->err.decrypt.count++;
        return 0;
    }
    union mud_sockaddr local;

    if (mud_localaddr(&local, &msg))
        return 0;

    mud_path* path = mud_get_path(m, &local, &remote, MUD_PASSIVE);

    if (!path || path->conf.state <= MUD_DOWN)
        return 0;

    if (MUD_MSG(sent_time)) {
        mud_recv_msg(m, path, now, sent_time, (unsigned char*)data, (size_t)packet_size);
    } else {
        path->idle = now;
    }
    path->rx.total++;
    path->rx.time = now;
    path->rx.bytes += (size_t)packet_size;

    m->last_recv_time = now;

    return MUD_MSG(sent_time) ? 0 : (int)ret;
}