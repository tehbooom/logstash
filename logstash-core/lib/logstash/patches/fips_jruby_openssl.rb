# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

# Load jruby-openssl's Java extension before referencing SecurityHelper. The
# extension's strict FIPS contract resolves deployment-registered providers by
# name and version, and fails instead of falling back when they do not match.
#
# This must run before any `require "openssl"` anywhere in the process, because
# the provider contract is configured while the OpenSSL extension is loaded.
#
# Mechanism:
#   -Djruby.openssl.fips.provider=BCFIPS:2* requires the JCE provider.
#   -Djruby.openssl.fips.ssl.provider=BCJSSE:2* requires the JSSE provider.
#
# The FIPS gem is BC-free. The deployment remains responsible for loading and
# registering BCFIPS and BCJSSE through java.security before JRuby starts.
# jruby.openssl.provider.register=false prevents the legacy registration path.

jce_requirement = java.lang.System.getProperty("jruby.openssl.fips.provider")
ssl_requirement = java.lang.System.getProperty("jruby.openssl.fips.ssl.provider")

if jce_requirement || ssl_requirement
  # Fail fast if openssl was already required before this patch ran. Once
  # SecurityHelper has initialized its legacy provider, strict configuration can
  # no longer establish the intended load ordering.
  require "jopenssl.jar"

  security_helper = org.jruby.ext.openssl.SecurityHelper
  if defined?(OpenSSL) &&
      !security_helper.isRequiredProviderMode &&
      security_helper.isProviderRegistered
    raise "fips_jruby_openssl must be required before 'openssl': " \
          "SecurityHelper already initialized its legacy security provider"
  end

  # Engage the fork's strict contract before the rest of Logstash can require
  # openssl.
  security_helper.configureRequiredProvider
  security_helper.configureRequiredSslProvider
end
