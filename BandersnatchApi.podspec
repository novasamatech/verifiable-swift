Pod::Spec.new do |s|
  s.name         = "BandersnatchApi"
  s.version      = "0.2.0"
  s.summary      = "Swift wrapper for the bandersnatch vrf crypto"
  s.homepage     = "https://github.com/novasamatech/verifiable-swift"
  s.license      = 'MIT'
  s.author       = {'Ruslan Rezin' => 'ruslan@novasama.io'}
  s.source       = { :git => 'https://github.com/novasamatech/verifiable-swift',  :tag => "#{s.version}"}

  s.ios.deployment_target = '12.0'
  s.swift_version = '5.0'

  s.vendored_frameworks = 'bindings/xcframework/verifiable_crypto.xcframework'
  s.source_files = 'Sources/**/*.swift'

end
