#include <iostream>
#include "../mud.h"

mud::path* mud::paths_get_path(paths* p, path_conf c, uint64_t now) {
    if (c.local.sa.sa_family != c.remote.sa.sa_family) {
        errno = EINVAL;
        return NULL;
    }
    for (unsigned i = 0; i < p->count; i++) {
        ::mud::path* path = &p->path[i];

        if (path->conf.state == EMPTY)
            continue;

        if (sockaddress_cmp_addr(&c.local, &path->conf.local)   ||
            sockaddress_cmp_addr(&c.remote, &path->conf.remote) ||
            sockaddress_cmp_port(&c.remote, &path->conf.remote))
            continue;

        return path;
    }
    if (c.state <= DOWN) {
        errno = 0;
        return NULL;
    }
    ::mud::path* path = NULL;

    for (unsigned i = 0; i < p->count; i++) {
        if (p->path[i].conf.state == EMPTY) {
            path = &p->path[i];
            break;
        }
    }
    if (!path) {
        if (p->count == MUD_PATH_MAX) {
            errno = ENOMEM;
            return NULL;
        }
        ::mud::path* paths = (::mud::path*)realloc(p->path, (p->count + 1) * sizeof(::mud::path));

        if (!paths)
            return NULL;

        path = &paths[p->count];

        p->count++;
        p->path = paths;
    }

    memset(path, 0, sizeof(::mud::path));

    path->conf.local      = c.local;
    path->conf.remote     = c.remote;
    path->conf.state      = c.state;
    path->conf.beat       = 100 * MUD_ONE_MSEC;
    path->conf.fixed_rate = 1;
    path->conf.loss_limit = 255;
    path->status          = PROBING;
    path->idle            = now;

    return path;
}