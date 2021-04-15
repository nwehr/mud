#include "../mud.h"

int mud::sockaddress_localaddr(sockaddress* addr, msghdr *msg) {
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
            sockaddress_unmapv4(addr);
            return 0;
        }
    }
    return 1;
}

void mud::sockaddress_from_addr(sockaddress* sock, addr* addr) {
    if (addr_is_v6(addr)) {
        sock->sin6.sin6_family = AF_INET6;
        memcpy(&sock->sin6.sin6_addr, addr->v6, 16);
        memcpy(&sock->sin6.sin6_port, addr->port, 2);
    } else {
        sock->sin.sin_family = AF_INET;
        memcpy(&sock->sin.sin_addr, addr->v4, 4);
        memcpy(&sock->sin.sin_port, addr->port, 2);
    }
}

void mud::sockaddress_unmapv4(sockaddress* addr) {
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

int mud::sockaddress_cmp_addr(sockaddress* a, sockaddress* b) {
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

int mud::sockaddress_cmp_port(sockaddress* a, sockaddress* b) {
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