#include "../mud.h"

void mud::path_update_mtu(path* p, size_t size) {
    if (!p->mtu.probe) {
        if (!p->mtu.last) {
            p->mtu.min = MUD_MTU_MIN;
            p->mtu.max = MUD_MTU_MAX;
            p->mtu.probe = MUD_MTU_MAX;
        }
        return;
    }
    if (size) {
        if (p->mtu.min > size || p->mtu.max < size)
            return;
        p->mtu.min = size + 1;
        p->mtu.last = size;
    } else {
        p->mtu.max = p->mtu.probe - 1;
    }

    size_t probe = (p->mtu.min + p->mtu.max) >> 1;

    if (p->mtu.min > p->mtu.max) {
        p->mtu.probe = 0;
    } else {
        p->mtu.probe = probe;
    }
}

void mud::path_update_rl(path* p, uint64_t now, uint64_t tx_dt, uint64_t tx_bytes, uint64_t tx_pkt, uint64_t rx_dt, uint64_t rx_bytes, uint64_t rx_pkt) {
    if (rx_dt && rx_dt > tx_dt + (tx_dt >> 3)) {
        if (!p->conf.fixed_rate)
            p->tx.rate = (7 * rx_bytes * MUD_ONE_SEC) / (8 * rx_dt);
    } else {
        uint64_t tx_acc = p->msg.tx.acc + tx_pkt;
        uint64_t rx_acc = p->msg.rx.acc + rx_pkt;

        if (tx_acc > 1000) {
            if (tx_acc >= rx_acc)
                p->tx.loss = (tx_acc - rx_acc) * 255U / tx_acc;
            p->msg.tx.acc = tx_acc - (tx_acc >> 4);
            p->msg.rx.acc = rx_acc - (rx_acc >> 4);
        } else {
            p->msg.tx.acc = tx_acc;
            p->msg.rx.acc = rx_acc;
        }

        if (!p->conf.fixed_rate)
            p->tx.rate += p->tx.rate / 10;
    }
    if (p->tx.rate > p->conf.tx_max_rate)
        p->tx.rate = p->conf.tx_max_rate;
}