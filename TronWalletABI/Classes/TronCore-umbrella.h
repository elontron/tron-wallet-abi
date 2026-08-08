#ifdef __OBJC__
#import <UIKit/UIKit.h>
#else
#ifndef FOUNDATION_EXPORT
#if defined(__cplusplus)
#define FOUNDATION_EXPORT extern "C"
#else
#define FOUNDATION_EXPORT extern
#endif
#endif
#endif

// Curated umbrella. The vendored trezor headers are pulled in transitively and in
// dependency order by TrezorCrypto.h; importing them individually (as a generated
// umbrella would) breaks because several are macro fragments, not standalone headers.
#import "EthereumCrypto.h"
#import "TrezorCrypto.h"

FOUNDATION_EXPORT double TronCoreVersionNumber;
FOUNDATION_EXPORT const unsigned char TronCoreVersionString[];
