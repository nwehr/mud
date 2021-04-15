#if defined __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#if defined __linux__ && !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../mud.h"

static int mud_send_msg(mud::mud* m, mud::path* path, uint64_t now, uint64_t sent_time, uint64_t fw_bytes, uint64_t fw_total, size_t size);

static inline int mud_encrypt_opt(const mud::crypto_key* k, const mud::crypto_opt* c) {
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

static inline int mud_decrypt_opt(const mud::crypto_key* k, const mud::crypto_opt* c) {
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

static inline int mud_timeout(uint64_t now, uint64_t last, uint64_t timeout) {
    return (!last) || (MUD_TIME_MASK(now - last) >= timeout);
}

static mud::path* mud_select_path(mud::mud* m, uint16_t cursor) {
    uint64_t k = (cursor * m->rate) >> 16;

    for (unsigned i = 0; i < m->paths.count; i++) {
        mud::path* path = &m->paths.path[i];

        if (path->status != mud::RUNNING)
            continue;

        if (k < path->tx.rate)
            return path;

        k -= path->tx.rate;
    }
    return NULL;
}

uint64_t mud::mud_now(mud* m) {
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

int mud::mud_get_errors(mud* m, errors* err) {
    if (!err) {
        errno = EINVAL;
        return -1;
    }
    memcpy(err, &m->err, sizeof(errors));
    return 0;
}

int mud::mud_set_conf(mud* m, conf* conf) {
    if (conf->keepalive) {
        m->conf.keepalive = conf->keepalive;
    }

    if (conf->timetolerance) {
        m->conf.timetolerance = conf->timetolerance;
    }

    if (conf->kxtimeout) {
        m->conf.kxtimeout  = conf->kxtimeout;
    }

    return 0;
}

size_t mud::mud_get_mtu(mud* m) {
    if (!m->mtu)
        return 0;

    return m->mtu - MUD_PKT_MIN_SIZE;
}

static int mud_keyx(mud::keyx_t* kx, unsigned char* remote, int aes) {
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

static int mud_keyx_init(mud::mud* m, uint64_t now) {
    mud::keyx_t* kx = &m->keyx;

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

mud::mud* mud::mud_create(sockaddress* addr, unsigned char* key, int* aes) {
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

    auto mud_setup_socket = [](int fd, int v4, int v6) {
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
    };

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

int mud::mud_get_fd(mud* m) {
    if (!m)
        return -1;

    return m->fd;
}

void mud::mud_delete(mud* m) {
    if (!m)
        return;

    if (m->paths.path)
        free(m->paths.path);

    if (m->fd >= 0)
        close(m->fd);

    sodium_free(m);
}

static size_t mud_encrypt(mud::mud* m, uint64_t now, unsigned char* dst, size_t dst_size, const unsigned char* src, size_t src_size) {
    const size_t size = src_size + MUD_PKT_MIN_SIZE;

    if (size > dst_size)
        return 0;

    const mud::crypto_opt opt = {
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

static size_t mud_decrypt(mud::mud* m, unsigned char* dst, size_t dst_size, const unsigned char* src, size_t src_size) {
    const size_t size = src_size - MUD_PKT_MIN_SIZE;

    if (size > dst_size)
        return 0;

    const mud::crypto_opt opt = {
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

static size_t mud_decrypt_msg(mud::mud* m, unsigned char* dst, size_t dst_size, const unsigned char* src, size_t src_size) {
    const size_t size = src_size - MUD_PKT_MIN_SIZE;

    if (size < sizeof(mud::msg) || size > dst_size)
        return 0;

    const mud::crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = src_size,
    };

    if (mud_decrypt_opt(&m->keyx.priv, &opt))
        return 0;

    return size;
}

static int mud_path_update(mud::mud* m, mud::path* path, uint64_t now) {
    switch (path->conf.state) {
    case mud::DOWN:
        path->status = mud::DELETING;
        if (mud_timeout(now, path->rx.time, 2 * MUD_ONE_MIN))
            memset(path, 0, sizeof(mud::path));
        return 0;
    case mud::PASSIVE:
        if (mud_timeout(now, m->last_recv_time, 2 * MUD_ONE_MIN)) {
            memset(path, 0, sizeof(mud::path));
            return 0;
        }
    case mud::UP: break;
    default:     return 0;
    }
    if (path->msg.sent >= MUD_MSG_SENT_MAX) {
        if (path->mtu.probe) {
            path_update_mtu(path, 0);
            path->msg.sent = 0;
        } else {
            path->msg.sent = MUD_MSG_SENT_MAX;
            path->status =mud::DEGRADED;
            return 0;
        }
    }
    if (!path->mtu.ok) {
        path->status = mud::PROBING;
        return 0;
    }
    if (path->tx.loss > path->conf.loss_limit ||
        path->rx.loss > path->conf.loss_limit) {
        path->status = mud::LOSSY;
        return 0;
    }
    if (path->conf.state == mud::PASSIVE &&
        mud_timeout(m->last_recv_time, path->rx.time,
                    MUD_MSG_SENT_MAX * path->conf.beat)) {
        path->status = mud::WAITING;
        return 0;
    }
    if (path->conf.pref > m->pref) {
        path->status = mud::READY;
    } else if (path->status != mud::RUNNING) {
        path->status = mud::RUNNING;
        path->idle = now;
    }
    return 1;
}

static uint64_t mud_path_track(mud::mud* m, mud::path* path, uint64_t now) {
    if (path->conf.state != mud::UP)
        return now;

    uint64_t timeout = path->conf.beat;

    switch (path->status) {
        case mud::RUNNING:
            if (mud_timeout(now, path->idle, MUD_ONE_SEC))
                timeout = m->conf.keepalive;
            break;
        case mud::DEGRADED:
        case mud::LOSSY:
        case mud::PROBING:
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

static void mud_update_window(mud::mud* m, const uint64_t now) {
    uint64_t elapsed = MUD_TIME_MASK(now - m->window_time);

    if (elapsed > MUD_ONE_MSEC) {
        m->window += m->rate * elapsed / MUD_ONE_SEC;
        m->window_time = now;
    }
    uint64_t window_max = m->rate * 100 * MUD_ONE_MSEC / MUD_ONE_SEC;

    if (m->window > window_max)
        m->window = window_max;
}

int mud::mud_update(mud* m) {
    unsigned count = 0;
    unsigned pref = 255;
    unsigned next_pref = 255;
    uint64_t rate = 0;
    size_t   mtu = 0;
    uint64_t now = mud_now(m);

    if (!mud_keyx_init(m, now))
        now = mud_now(m);

    for (unsigned i = 0; i < m->paths.count; i++) {
        ::mud::path* path = &m->paths.path[i];

        if (mud_path_update(m, path, now)) {
            if (next_pref > path->conf.pref && path->conf.pref > m->pref)
                next_pref = path->conf.pref;
            if (pref > path->conf.pref)
                pref = path->conf.pref;
            if (path->status == RUNNING)
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

        for (unsigned i = 0; i < m->paths.count; i++) {
            ::mud::path* path = &m->paths.path[i];

            if (!mud_path_update(m, path, now))
                continue;

            if (path->status == RUNNING)
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



static int mud_send_path(mud::mud* m, mud::path* path, uint64_t now, void *data, size_t size, int flags) {
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

static int mud_send_msg(mud::mud* m, mud::path* path, uint64_t now, uint64_t sent_time, uint64_t fw_bytes, uint64_t fw_total, size_t size) {
    unsigned char dst[MUD_PKT_MAX_SIZE];
    unsigned char src[MUD_PKT_MAX_SIZE] = {0};
    ::mud::msg *msg = (::mud::msg *)src;

    if (size < MUD_PKT_MIN_SIZE + sizeof(::mud::msg))
        size = MUD_PKT_MIN_SIZE + sizeof(::mud::msg);

    mud_store(dst, MUD_MSG_MARK(now), MUD_TIME_SIZE);
    MUD_STORE_MSG(msg->sent_time, sent_time);

    if (addr_from_sockaddress(&msg->addr, &path->conf.remote))
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

    const mud::crypto_opt opt = {
        .dst = dst,
        .src = src,
        .size = size - MUD_PKT_MIN_SIZE,
    };
    mud_encrypt_opt(&m->keyx.priv, &opt);

    return mud_send_path(m, path, now, dst, size, sent_time ? MSG_CONFIRM : 0);
}

int mud::mud_send(mud* m, const void* plain, size_t plain_size) {
    if (!plain_size)
        return 0;

    if (m->window < 1500) {
        errno = EAGAIN;
        return -1;
    }

    const uint64_t now = mud_now(m);
    unsigned char encrypted_data[MUD_PKT_MAX_SIZE];
    const size_t encrypted_size = mud_encrypt(m, now, encrypted_data, sizeof(encrypted_data), (const unsigned char*)plain, plain_size);

    if (!encrypted_size) {
        errno = EMSGSIZE;
        return -1;
    }

    uint16_t k;
    memcpy(&k, &encrypted_data[encrypted_size - sizeof(k)], sizeof(k));

    ::mud::path* path = mud_select_path(m, k);

    if (!path) {
        errno = EAGAIN;
        return -1;
    }
    path->idle = now;

    return mud_send_path(m, path, now, encrypted_data, encrypted_size, 0);
}

int mud_send_wait(mud::mud* m) {
    return m->window < 1500;
}

static void mud_recv_msg(mud::mud* m, mud::path* path, uint64_t now, uint64_t sent_time, unsigned char* data, size_t size) {
    mud::msg *msg = (mud::msg*)data;
    const uint64_t tx_time = MUD_LOAD_MSG(msg->sent_time);

    mud::sockaddress_from_addr(&path->remote, &msg->addr);

    if (tx_time) {
        mud::stat_update(&path->rtt, MUD_TIME_MASK(now - tx_time));

        const uint64_t tx_bytes = MUD_LOAD_MSG(msg->fw.bytes);
        const uint64_t tx_total = MUD_LOAD_MSG(msg->fw.total);
        const uint64_t rx_bytes = MUD_LOAD_MSG(msg->rx.bytes);
        const uint64_t rx_total = MUD_LOAD_MSG(msg->rx.total);
        const uint64_t rx_time  = sent_time;

        if ((tx_time > path->msg.tx.time) && (tx_bytes > path->msg.tx.bytes) &&
            (rx_time > path->msg.rx.time) && (rx_bytes > path->msg.rx.bytes)) {
            if (path->msg.set && path->status > mud::PROBING) {
                path_update_rl(path, now,
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

        if (path->conf.state == mud::PASSIVE)
            return;

        path_update_mtu(path, size);

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
    } else if (path->conf.state == mud::UP) {
        m->keyx.use_next = 1;
    }
    mud_send_msg(m, path, now, sent_time,
                 MUD_LOAD_MSG(msg->tx.bytes),
                 MUD_LOAD_MSG(msg->tx.total),
                 size);
}

int mud::mud_recv(mud* m, void *data, size_t size) {
    sockaddress remote;
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

    sockaddress_unmapv4(&remote);

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
    sockaddress local;

    if (sockaddress_localaddr(&local, &msg))
        return 0;

    ::mud::path* path = paths_get_path(&m->paths, {.local = local, .remote = remote, .state = PASSIVE}, mud_now(m));

    if (!path || path->conf.state <= DOWN)
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