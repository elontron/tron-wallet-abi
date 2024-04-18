#
# Be sure to run `pod lib lint TronWalletABI.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'TronWalletABI'
  s.version          = '1.0.0'
  s.summary          = 'Core Tron data structures and algorithms.'

  s.homepage         = 'https://github.com/TronLink/TronWalletABI'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = 'tronlinkdev'
  s.source           = { :git => 'https://github.com/TronLink/TronWalletABI.git', :tag => s.version.to_s }
  s.platform = :ios, '10.0'
  s.ios.deployment_target = '10.0'

  s.source_files = 'TronWalletABI/Classes/**/*'
  s.module_name = 'TronCore'
  s.dependency 'BigInt'
  s.dependency 'TrezorCrypto', '~> 0.0.8'
  s.dependency 'SwiftProtobuf', '~> 1.0'

  s.pod_target_xcconfig = { 'SWIFT_OPTIMIZATION_LEVEL' => '-Owholemodule' }
  s.public_header_files = 'TronWalletABI/Classes/*.h'
end
