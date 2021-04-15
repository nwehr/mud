#include "../mud.h"

void mud::path_update_mtu(path* path, size_t size) {
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