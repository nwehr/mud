#if defined __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#if defined __linux__ && !defined _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "../mud.h"

static int mud_send_msg(mud::mud* m, mud::path* path, uint64_t now, uint64_t sent_time, uint64_t fw_bytes, uint64_t fw_total, size_t size);

void mud_store(unsigned char* dst, uint64_t src, size_t size) {
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

uint64_t mud_load(const unsigned char* src, size_t size) {
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

int mud_timeout(uint64_t now, uint64_t last, uint64_t timeout) {
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
        auto mud_sso_int = [](int fd, int level, int optname, int opt) {
            return setsockopt(fd, level, optname, &opt, sizeof(opt));
        };

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

    memcpy(m->keys.priv.encrypt.key, key, MUD_KEY_SIZE);
    memcpy(m->keys.priv.decrypt.key, key, MUD_KEY_SIZE);
    sodium_memzero(key, MUD_KEY_SIZE);

    m->keys.current = m->keys.priv;
    m->keys.next = m->keys.priv;
    m->keys.last = m->keys.priv;

    if (*aes && !aegis256_is_available())
        *aes = 0;

    m->keys.aes = *aes;
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

static size_t mud_decrypt_msg(mud::mud* m, unsigned char* dst, size_t dst_size, const unsigned char* src, size_t src_size) {
    const size_t size = src_size - MUD_PKT_MIN_SIZE;

    if (size < sizeof(mud::msg) || size > dst_size){
        return 0;
    }

    if (crypto_key_decrypt(&m->keys.priv, src, dst, src_size)) {
        return 0;
    }

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

int mud::mud_update(mud* m) {
    unsigned count = 0;
    unsigned pref = 255;
    unsigned next_pref = 255;
    uint64_t rate = 0;
    size_t   mtu = 0;
    uint64_t now = mud_now(m);

    if (!crypto_keys_init(&m->keys, now, m->conf.kxtimeout))
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

    uint64_t elapsed = MUD_TIME_MASK(now - m->window_time);

    if (elapsed > MUD_ONE_MSEC) {
        m->window += m->rate * elapsed / MUD_ONE_SEC;
        m->window_time = now;
    }
    uint64_t window_max = m->rate * 100 * MUD_ONE_MSEC / MUD_ONE_SEC;

    if (m->window > window_max)
        m->window = window_max;

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

    memcpy(msg->pkey, m->keys.local, sizeof(m->keys.local));
    msg->aes = (unsigned char)m->keys.aes;

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

    crypto_key_encrypt(&m->keys.priv, src, dst, size - MUD_PKT_MIN_SIZE);

    return mud_send_path(m, path, now, dst, size, sent_time ? MSG_CONFIRM : 0);
}

int mud::mud_send(mud* m, const unsigned char* plain, size_t plain_size) {
    if (!plain_size)
        return 0;

    if (m->window < 1500) {
        errno = EAGAIN;
        return -1;
    }

    const uint64_t now = mud_now(m);
    unsigned char encrypted_data[MUD_PKT_MAX_SIZE];
    const size_t encrypted_size = crypto_keys_encrypt(&m->keys, now, encrypted_data, sizeof(encrypted_data), plain, plain_size);

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
    if (memcmp(msg->pkey, m->keys.remote, MUD_PUBKEY_SIZE)) {
        if (crypto_keys_exchange(&m->keys, msg->pkey, msg->aes)) {
            m->err.keyx.addr = path->conf.remote;
            m->err.keyx.time = now;
            m->err.keyx.count++;
            return;
        }
    } else if (path->conf.state == mud::UP) {
        m->keys.use_next = 1;
    }
    mud_send_msg(m, path, now, sent_time,
                 MUD_LOAD_MSG(msg->tx.bytes),
                 MUD_LOAD_MSG(msg->tx.total),
                 size);
}

int mud::mud_recv(mud* m, unsigned char* data, size_t size) {
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

    const size_t packet_size = recvmsg(m->fd, &msg, 0);

    if (packet_size == (size_t)-1)
        return -1;

    if ((msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || (packet_size <= MUD_PKT_MIN_SIZE))
        return 0;

    const uint64_t now = mud_now(m);
    const uint64_t sent_time = mud_load(packet, MUD_TIME_SIZE);

    sockaddress_unmapv4(&remote);

    if ((MUD_TIME_MASK(now - sent_time) > m->conf.timetolerance) && (MUD_TIME_MASK(sent_time - now) > m->conf.timetolerance)) {
        m->err.clocksync.addr = remote;
        m->err.clocksync.time = now;
        m->err.clocksync.count++;
        return 0;
    }
    
    const size_t ret = MUD_MSG(sent_time)
                     ? mud_decrypt_msg(m, data, size, packet, packet_size)
                     : crypto_keys_decrypt(&m->keys, data, size, packet, packet_size);
    
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
        mud_recv_msg(m, path, now, sent_time, data, packet_size);
    } else {
        path->idle = now;
    }
    path->rx.total++;
    path->rx.time = now;
    path->rx.bytes += packet_size;

    m->last_recv_time = now;

    return MUD_MSG(sent_time) ? 0 : (int)ret;
}