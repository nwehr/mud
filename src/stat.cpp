#include "../mud.h"

void mud::stat_update(stat* stat, const uint64_t val) {
    auto abs_diff = [](uint64_t a, uint64_t b) {
        return (a >= b) ? a - b : b - a;
    };

    if (stat->setup) {
        const uint64_t var = abs_diff(stat->val, val);
        stat->var = ((stat->var << 1) + stat->var + var) >> 2;
        stat->val = ((stat->val << 3) - stat->val + val) >> 3;
    } else {
        stat->setup = 1;
        stat->var = val >> 1;
        stat->val = val;
    }
}