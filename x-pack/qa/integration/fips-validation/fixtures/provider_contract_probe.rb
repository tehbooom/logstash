require "bundler/setup"
require "jopenssl.jar"

unless java.security.Security.getProvider("BCFIPS")
  bcfips_class = Java::OrgBouncycastleJcajceProvider::BouncyCastleFipsProvider
  java.security.Security.insertProviderAt(bcfips_class.new("C:HYBRID;ENABLE{All};"), 1)
end
unless java.security.Security.getProvider("BCJSSE")
  bcjsse_class = Java::OrgBouncycastleJsseProvider::BouncyCastleJsseProvider
  java.security.Security.insertProviderAt(bcjsse_class.new("fips:BCFIPS"), 2)
end

security_helper = org.jruby.ext.openssl.SecurityHelper
security_helper.configureRequiredProvider
security_helper.configureRequiredSslProvider
digest = security_helper.getMessageDigest("SHA-256")
digest_bytes = digest.digest("strict-provider-contract".to_java_bytes)
ssl_context = security_helper.getSSLContext("TLS")

puts [
  "FIPS_PROVIDER_CONTRACT",
  "required=#{security_helper.isRequiredProviderMode}",
  "jce_property=#{java.lang.System.getProperty("jruby.openssl.fips.provider")}",
  "jce_provider=#{digest.getProvider.getName}",
  "digest_bytes=#{digest_bytes.length}",
  "ssl_property=#{java.lang.System.getProperty("jruby.openssl.fips.ssl.provider")}",
  "ssl_provider=#{ssl_context.getProvider.getName}"
].join(" ")

begin
  require "jruby-openssl"
  puts "FIPS_COMPAT_REQUIRE loaded=true"
rescue StandardError, LoadError => e # the probe records the next initialization seam
  implementation = e.backtrace.find { |line| line.include?("/jruby-openssl-fips-") }
  puts "FIPS_COMPAT_REQUIRE resolved=#{implementation} next_seam=#{e.class}: #{e.message}"
end
