#include "../mud.h"

int mud::crypto_key_encrypt(const crypto_key* k, const unsigned char* src, unsigned char* dst, size_t size) {
    if (k->aes) {
        unsigned char npub[AEGIS256_NPUBBYTES] = {0};
        memcpy(npub, dst, MUD_TIME_SIZE);
        return aegis256_encrypt(
            dst + MUD_TIME_SIZE,
            NULL,
            src,
            size,
            dst,
            MUD_TIME_SIZE,
            npub,
            k->encrypt.key
        );
    } else {
        unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
        memcpy(npub, dst, MUD_TIME_SIZE);
        return crypto_aead_chacha20poly1305_encrypt(
            dst + MUD_TIME_SIZE,
            NULL,
            src,
            size,
            dst,
            MUD_TIME_SIZE,
            NULL,
            npub,
            k->encrypt.key
        );
    }
}

int mud::crypto_key_decrypt(const crypto_key* k, const unsigned char* src, unsigned char* dst, size_t size) {
    if (k->aes) {
        unsigned char npub[AEGIS256_NPUBBYTES] = {0};
        memcpy(npub, src, MUD_TIME_SIZE);
        return aegis256_decrypt(
            dst,
            NULL,
            src + MUD_TIME_SIZE,
            size - MUD_TIME_SIZE,
            src, MUD_TIME_SIZE,
            npub,
            k->decrypt.key
        );
    } else {
        unsigned char npub[crypto_aead_chacha20poly1305_NPUBBYTES] = {0};
        memcpy(npub, src, MUD_TIME_SIZE);
        return crypto_aead_chacha20poly1305_decrypt(
            dst,
            NULL,
            NULL,
            src + MUD_TIME_SIZE,
            size - MUD_TIME_SIZE,
            src, MUD_TIME_SIZE,
            npub,
            k->decrypt.key
        );
    }
}