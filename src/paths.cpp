#include <iostream>
#include "../mud.h"

mud::path* mud::paths_get_path(paths* p, sockaddress* local, sockaddress* remote, state state) {
    std::cout << "paths_get_path" << std::endl;

    if (local->sa.sa_family != remote->sa.sa_family) {
        errno = EINVAL;
        return nullptr;
    }

    for (unsigned i = 0; i < p->count; i++) {
        path* path = &p->path[i];

        if (path->conf.state == EMPTY)
            continue;

        if (sockaddress_cmp_addr(local, &path->conf.local)   ||
            sockaddress_cmp_addr(remote, &path->conf.remote) ||
            sockaddress_cmp_port(remote, &path->conf.remote))
            continue;

        return path;
    }

    if (state <= DOWN) {
        errno = 0;
        return nullptr;
    }

    path* path = nullptr;

    for (unsigned i = 0; i < p->count; i++) {
        if (p->path[i].conf.state == EMPTY) {
            path = &p->path[i];
            break;
        }
    }

    // Add a new path
    if (!path) {
        if (p->count == MUD_PATH_MAX) {
            errno = ENOMEM;
            return nullptr;
        }
        
        path = &(p->path[p->count]);
        p->count++;
    }

    memset(path, 0, sizeof(::mud::path));

    path->conf.local      = *local;
    path->conf.remote     = *remote;
    path->conf.state      = state;
    path->conf.beat       = 100 * MUD_ONE_MSEC;
    path->conf.fixed_rate = 1;
    path->conf.loss_limit = 255;
    path->status          = PROBING;
    path->idle            = time_now();

    return path;
}