@import Foundation;
@import Security;

#include <stdlib.h>

uint32_t random32(void) {
    uint32_t value;
    int status = SecRandomCopyBytes(kSecRandomDefault, sizeof(value), &value);
    if (status != errSecSuccess) {
        abort();
    }
    return value;
}

void random_buffer(uint8_t *buf, size_t len) {
    int status = SecRandomCopyBytes(kSecRandomDefault, len, buf);
    if (status != errSecSuccess) {
        abort();
    }
}
