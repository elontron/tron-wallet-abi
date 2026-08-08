#
# Be sure to run `pod lib lint TronWalletABI.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'TronWalletABI'
  s.version          = '1.0.3'
  s.summary          = 'Core Tron data structures and algorithms.'

  s.homepage         = 'https://github.com/TronLink/TronWalletABI'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = 'tronlinkdev'
  s.source           = { :git => 'https://github.com/TronLink/TronWalletABI.git', :tag => s.version.to_s }
  s.platform = :ios, '13.0'

  s.source_files = 'TronWalletABI/Classes/**/*.{h,m,c,swift}'
  # secp256k1.c / nist256p1.c #include these precomputed tables.
  s.preserve_paths = 'TronWalletABI/Classes/TrezorCrypto/trezor-crypto/*.table'
  s.module_name = 'TronCore'
  s.dependency 'BigInt'
  s.dependency 'SwiftProtobuf', '~> 1.0'

  # No header_mappings_dir, so CocoaPods flattens every public header into
  # TronCore.framework/Headers. The vendored trezor sources then resolve their bare
  # includes ("aes.h", "ed25519.h", ...) by the same-directory rule rather than
  # falling through to whatever else sits on the header search path.
  #
  # A generated umbrella would #import each public header on its own, which fails:
  # several trezor headers are macro fragments meant to be included mid-file. Hence
  # the hand-written umbrella below, which reaches all 47 real headers transitively.
  s.module_map = 'TronWalletABI/TronCore.modulemap'

  # Fragments and non-self-contained headers: kept out of Headers/ entirely. Nothing
  # in the module's include graph reaches them; only the .c files use them.
  trezor_headers = 'TronWalletABI/Classes/TrezorCrypto/trezor-crypto'
  s.private_header_files = [
    "#{trezor_headers}/nem_serialize.h",
    "#{trezor_headers}/bip39_english.h",
    "#{trezor_headers}/blake2_common.h",
    "#{trezor_headers}/check_mem.h",
    "#{trezor_headers}/groestl_internal.h",
    "#{trezor_headers}/aes/aesopt.h",
    "#{trezor_headers}/aes/aestab.h",
    "#{trezor_headers}/chacha20poly1305/ecrypt-machine.h",
    "#{trezor_headers}/chacha20poly1305/ecrypt-portable.h",
    "#{trezor_headers}/chacha20poly1305/poly1305-donna-32.h",
    "#{trezor_headers}/ed25519-donna/curve25519-donna-scalarmult-base.h",
    "#{trezor_headers}/ed25519-donna/ed25519-hash-custom.h",
    "#{trezor_headers}/ed25519-donna/ed25519-hash-custom-keccak.h",
    "#{trezor_headers}/ed25519-donna/ed25519-hash-custom-sha3.h",
    "#{trezor_headers}/ed25519-donna/ed25519-keccak.h",
    "#{trezor_headers}/ed25519-donna/ed25519-sha3.h"
  ]

  # Resolves cross-directory bare includes while compiling the vendored .c files.
  trezor = "$(PODS_TARGET_SRCROOT)/#{trezor_headers}"
  s.pod_target_xcconfig = {
    'SWIFT_OPTIMIZATION_LEVEL' => '-Owholemodule',
    'HEADER_SEARCH_PATHS' => "$(inherited) \"#{trezor}\" \"#{trezor}/aes\" \"#{trezor}/chacha20poly1305\" \"#{trezor}/ed25519-donna\""
  }
end
