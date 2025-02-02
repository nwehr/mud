#include "../mud.h"

int mud_timeout(uint64_t now, uint64_t last, uint64_t timeout);
void mud_store(unsigned char* dst, uint64_t src, size_t size);

static void hash_key(unsigned char* dst, unsigned char* key, unsigned char* secret, unsigned char* pk0, unsigned char* pk1) {
    crypto_generichash_state state;

    crypto_generichash_init(&state, key, MUD_KEY_SIZE, MUD_KEY_SIZE);
    crypto_generichash_update(&state, secret, crypto_scalarmult_BYTES);
    crypto_generichash_update(&state, pk0, MUD_PUBKEY_SIZE);
    crypto_generichash_update(&state, pk1, MUD_PUBKEY_SIZE);
    crypto_generichash_final(&state, dst, MUD_KEY_SIZE);

    sodium_memzero(&state, sizeof(state));
}

int mud::crypto_keys_init(crypto_keys* keys, uint64_t now, uint64_t timeout) {
    if (!mud_timeout(now, keys->time, timeout))
        return 1;

    static const unsigned char test[crypto_scalarmult_BYTES] = {
        0x9b, 0xf4, 0x14, 0x90, 0x0f, 0xef, 0xf8, 0x2d, 0x11, 0x32, 0x6e,
        0x3d, 0x99, 0xce, 0x96, 0xb9, 0x4f, 0x79, 0x31, 0x01, 0xab, 0xaf,
        0xe3, 0x03, 0x59, 0x1a, 0xcd, 0xdd, 0xb0, 0xfb, 0xe3, 0x49
    };
    unsigned char tmp[crypto_scalarmult_BYTES];

    do {
        randombytes_buf(keys->secret, sizeof(keys->secret));
        crypto_scalarmult_base(keys->local, keys->secret);
    } while (crypto_scalarmult(tmp, test, keys->local));

    sodium_memzero(tmp, sizeof(tmp));
    keys->time = now;

    return 0;
}

int mud::crypto_keys_exchange(crypto_keys* keys, unsigned char* remote_key, int aes) {
    unsigned char secret[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(secret, keys->secret, remote_key))
        return 1;

    hash_key(keys->next.encrypt.key, keys->priv.encrypt.key, secret, remote_key, keys->local);
    hash_key(keys->next.decrypt.key, keys->priv.encrypt.key, secret, keys->local, remote_key);

    sodium_memzero(secret, sizeof(secret));

    memcpy(keys->remote, remote_key, MUD_PUBKEY_SIZE);
    keys->next.aes = keys->aes && aes;

    return 0;
}

size_t mud::crypto_keys_encrypt(crypto_keys* keys, uint64_t now, unsigned char* dst, size_t dst_size, const unsigned char* src, size_t src_size) {
    const size_t size = src_size + MUD_PKT_MIN_SIZE;

    if (size > dst_size){
        return 0;
    }

    mud_store(dst, now, MUD_TIME_SIZE);

    if (keys->use_next) {
        crypto_key_encrypt(&keys->next, src, dst, src_size);
    } else {
        crypto_key_encrypt(&keys->current, src, dst, src_size);
    }

    return size;
}

size_t mud::crypto_keys_decrypt(crypto_keys* keys, unsigned char* dst, size_t dst_size, const unsigned char* src, size_t src_size) {
    const size_t size = src_size - MUD_PKT_MIN_SIZE;

    if (size > dst_size) {
        return 0; 
    }

    if (crypto_key_decrypt(&keys->current, src, dst, src_size)) {
        if (!crypto_key_decrypt(&keys->next, src, dst, src_size)) {
            keys->last = keys->current;
            keys->current = keys->next;
            keys->use_next = 0;
        } else {
            if (crypto_key_decrypt(&keys->last, src, dst, src_size) && crypto_key_decrypt(&keys->priv, src, dst, src_size)) {
                return 0;
            }
        }
    }
    
    return size;
}