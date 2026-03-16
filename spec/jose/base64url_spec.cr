require "../spec_helper"

describe JOSE::Base64Url do
  it "round-trips encode/decode" do
    data = Random::Secure.random_bytes(32)
    encoded = JOSE::Base64Url.encode(data)
    decoded = JOSE::Base64Url.decode(encoded)
    decoded.should eq(data)
  end

  it "produces no padding characters" do
    data = Random::Secure.random_bytes(31)
    encoded = JOSE::Base64Url.encode(data)
    encoded.includes?('=').should be_false
  end
end
