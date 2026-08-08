/*
 * Bounds check for mnemonic_to_seed(), pinned against known-answer seeds so that a salt
 * built or measured wrong fails here too. Not part of any build target; run it by hand
 * from the repository root:
 *
 *   clang -g -fsanitize=address -fobjc-arc -fmodules \
 *     -I TronWalletABI/Classes/TrezorCrypto/trezor-crypto \
 *     Scripts/bip39_seed_bounds_check.c \
 *     TronWalletABI/Classes/TrezorCrypto/trezor-crypto/bip39.c \
 *     TronWalletABI/Classes/TrezorCrypto/trezor-crypto/pbkdf2.c \
 *     TronWalletABI/Classes/TrezorCrypto/trezor-crypto/hmac.c \
 *     TronWalletABI/Classes/TrezorCrypto/trezor-crypto/sha2.c \
 *     TronWalletABI/Classes/TrezorCrypto/trezor-crypto/memzero.c \
 *     TronWalletABI/Classes/TrezorCrypto/util/SecRandom.m \
 *     -framework Security -framework Foundation -o /tmp/bip39_bounds && /tmp/bip39_bounds
 *
 * Before the length guard was added, the over-limit case wrote past salt[8 + 256] and
 * AddressSanitizer reported a stack-buffer-overflow instead of these checks passing.
 *
 * Deliberately not using assert(): the App's Release configuration compiles with -DNDEBUG,
 * and a check that disappears under the flag the shipping build uses is not a check.
 */

#include <stdio.h>
#include <string.h>

#include "bip39.h"

static int failures = 0;

static void check(int ok, const char *what)
{
	if (!ok) {
		printf("FAIL: %s\n", what);
		failures++;
	}
}

static int seed_is_zero(const uint8_t *seed)
{
	for (size_t i = 0; i < 64; i++) {
		if (seed[i] != 0) {
			return 0;
		}
	}
	return 1;
}

// Expected seeds for the mnemonic below, from PBKDF2-HMAC-SHA512 over salt "mnemonic" ||
// passphrase, 2048 rounds. The first is BIP39 English test vector #2. Checking the bytes
// rather than just "not all zero" is what catches a salt that is built or measured wrong:
// a miscomputed salt length still derives a perfectly non-zero, perfectly wrong seed.
static const uint8_t expected_trezor[64] = {
	0x2e, 0x89, 0x05, 0x81, 0x9b, 0x87, 0x23, 0xfe,
	0x2c, 0x1d, 0x16, 0x18, 0x60, 0xe5, 0xee, 0x18,
	0x30, 0x31, 0x8d, 0xbf, 0x49, 0xa8, 0x3b, 0xd4,
	0x51, 0xcf, 0xb8, 0x44, 0x0c, 0x28, 0xbd, 0x6f,
	0xa4, 0x57, 0xfe, 0x12, 0x96, 0x10, 0x65, 0x59,
	0xa3, 0xc8, 0x09, 0x37, 0xa1, 0xc1, 0x06, 0x9b,
	0xe3, 0xa3, 0xa5, 0xbd, 0x38, 0x1e, 0xe6, 0x26,
	0x0e, 0x8d, 0x97, 0x39, 0xfc, 0xe1, 0xf6, 0x07,
};

static const uint8_t expected_at_limit[64] = {
	0xb8, 0xd2, 0x8e, 0xe7, 0x4d, 0x44, 0xaa, 0xb4,
	0x7b, 0x68, 0x4d, 0x68, 0x4b, 0x2b, 0x16, 0x9a,
	0x3c, 0x2e, 0x1d, 0xca, 0xb9, 0xb3, 0xed, 0xea,
	0x46, 0xaa, 0x76, 0x8c, 0xf9, 0x3d, 0xf9, 0xee,
	0x22, 0xfc, 0xb6, 0xc9, 0x83, 0x78, 0x0e, 0x9c,
	0xed, 0xc1, 0xaa, 0x03, 0x48, 0x72, 0x54, 0x57,
	0x33, 0x71, 0x94, 0x74, 0x3c, 0x3a, 0x8f, 0x75,
	0x05, 0xe2, 0x8e, 0xd1, 0xea, 0x0b, 0xce, 0x74,
};

static const uint8_t expected_empty[64] = {
	0x87, 0x83, 0x86, 0xef, 0xb7, 0x88, 0x45, 0xb3,
	0x35, 0x5b, 0xd1, 0x5e, 0xa4, 0xd3, 0x9e, 0xf9,
	0x7d, 0x17, 0x9c, 0xb7, 0x12, 0xb7, 0x7d, 0x5c,
	0x12, 0xb6, 0xbe, 0x41, 0x5f, 0xff, 0xef, 0xfe,
	0x5f, 0x37, 0x7b, 0xa0, 0x2b, 0xf3, 0xf8, 0x54,
	0x4a, 0xb8, 0x00, 0xb9, 0x55, 0xe5, 0x1f, 0xbf,
	0xf0, 0x98, 0x28, 0xf6, 0x82, 0x05, 0x2a, 0x20,
	0xfa, 0xa6, 0xad, 0xdb, 0xbd, 0xdf, 0xb0, 0x96,
};

int main(void)
{
	const char *mnemonic = "legal winner thank year wave sausage worth useful legal winner thank yellow";
	uint8_t seed[64];

	check(mnemonic_to_seed(mnemonic, "TREZOR", seed, NULL) == 1, "BIP39 test vector is accepted");
	check(memcmp(seed, expected_trezor, sizeof(expected_trezor)) == 0, "BIP39 test vector derives the published seed");

	char at_limit[BIP39_MAX_PASSPHRASE_LENGTH + 1];
	memset(at_limit, 'x', BIP39_MAX_PASSPHRASE_LENGTH);
	at_limit[BIP39_MAX_PASSPHRASE_LENGTH] = 0;
	check(mnemonic_to_seed(mnemonic, at_limit, seed, NULL) == 1, "passphrase exactly at the limit is accepted");
	check(memcmp(seed, expected_at_limit, sizeof(expected_at_limit)) == 0, "passphrase at the limit salts with all 256 bytes");

	char over_limit[BIP39_MAX_PASSPHRASE_LENGTH + 2];
	memset(over_limit, 'x', BIP39_MAX_PASSPHRASE_LENGTH + 1);
	over_limit[BIP39_MAX_PASSPHRASE_LENGTH + 1] = 0;
	memset(seed, 0xAA, sizeof(seed));
	check(mnemonic_to_seed(mnemonic, over_limit, seed, NULL) == 0, "one character over the limit is rejected");
	check(seed_is_zero(seed), "rejected passphrase leaves no stale seed bytes behind");

	memset(seed, 0xAA, sizeof(seed));
	check(mnemonic_to_seed(mnemonic, NULL, seed, NULL) == 0, "NULL passphrase is rejected instead of crashing");
	check(mnemonic_to_seed(NULL, "", seed, NULL) == 0, "NULL mnemonic is rejected instead of crashing");
	check(seed_is_zero(seed), "NULL input leaves no stale seed bytes behind");

	check(mnemonic_to_seed(mnemonic, "", seed, NULL) == 1, "empty passphrase still derives a seed");
	check(memcmp(seed, expected_empty, sizeof(expected_empty)) == 0, "empty passphrase salts with bare \"mnemonic\"");

	if (failures) {
		printf("bip39 seed bounds: %d check(s) FAILED\n", failures);
		return 1;
	}
	printf("bip39 seed bounds: OK\n");
	return 0;
}
