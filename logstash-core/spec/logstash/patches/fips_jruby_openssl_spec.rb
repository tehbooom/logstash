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

require "spec_helper"

describe "fips_jruby_openssl patch" do
  def load_patch
    load File.expand_path("../../../lib/logstash/patches/fips_jruby_openssl.rb", __dir__)
  end

  around do |example|
    properties = [
      "jruby.openssl.fips.provider",
      "jruby.openssl.fips.ssl.provider"
    ]
    saved = properties.to_h { |property| [property, java.lang.System.getProperty(property)] }
    properties.each { |property| java.lang.System.clearProperty(property) }
    example.run
  ensure
    saved.each do |property, value|
      value ? java.lang.System.setProperty(property, value) : java.lang.System.clearProperty(property)
    end
  end

  it "does not resolve the FIPS-only Java surface on a non-FIPS launch" do
    expect { load_patch }.not_to raise_error
  end

  it "loads jopenssl.jar before referencing SecurityHelper" do
    source = File.read(File.expand_path("../../../lib/logstash/patches/fips_jruby_openssl.rb", __dir__))
    expect(source.index('require "jopenssl.jar"')).to be < source.index("org.jruby.ext.openssl.SecurityHelper")
  end

  it "uses the strict contract instead of the legacy imperative override" do
    source = File.read(File.expand_path("../../../lib/logstash/patches/fips_jruby_openssl.rb", __dir__))
    expect(source).to include("configureRequiredProvider", "configureRequiredSslProvider")
    expect(source).not_to include(".setSecurityProvider")
  end
end
