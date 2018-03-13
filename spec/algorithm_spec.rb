# frozen_string_literal: true

require 'base64'

RSpec.describe HttpSignatures::Algorithm do
  let(:input) { "the string\nto sign" }

  context 'using hmac' do
    let(:key) { 'the-key' }

    {
      'hmac-sha1' => 'bXPeVc5ySIyeUapN7mpMsJRnxVg=',
      'hmac-sha256' => 'hRQ5zpbGudR1hokS4PqeAkveKmz2dd8SCgV8OHcramI='
    }.each do |name, base64_signature|

      describe ".create('#{name}')" do
        let(:algorithm) { HttpSignatures::Algorithm.create(name) }

        it "has #name == '#{name}'" do
          expect(algorithm.name).to eq(name)
        end

        it 'produces known-good signature' do
          signature = algorithm.sign(key, input)
          expect(Base64.strict_encode64(signature)).to eq(base64_signature)
        end
      end
    end
  end

  context 'using rsa' do
    let(:key) { File.read('spec/files/test.pem') }

    {
      'rsa-sha1' => 'szJJTaZX7gSWVxCeRnMOEwKPZIG5oa5IhGkFlGUMUe5h5lyLIFiMYtLsjoY3dxPBKCH+52c6+2nYyynlvoSxgKNcz0gCFUvNRpvemRcAg0iYWFsIq0qDT7+scupHrmpAYNHnDAaplMkyBD3s8O0yesKkr81rj4bZQKkpZOcc+yA=',
      'rsa-sha256' => 'ScQsvMYSIQLqEem3bSTMaeukiryqRzYEoRhzxvS/yiVOmPQ4UmOEoZl85aFynwu7CMX2bN5bqlQYSk6n+qCcbxxaOfK89cJRe4Ejlr6Idiyf2d/IocOwVbEhqAa8qSv0t/ToD9RcraT8pHwEJZD383iV34v5gJcTudzLClLZ8wA='
    }.each do |name, base64_signature|

      describe ".create('#{name}')" do
        let(:algorithm) { HttpSignatures::Algorithm.create(name) }

        it "has #name == '#{name}'" do
          expect(algorithm.name).to eq(name)
        end

        it 'produces known-good signature' do
          signature = algorithm.sign(key, input)
          expect(Base64.strict_encode64(signature)).to eq(base64_signature)
        end
      end
    end
  end

  it 'raises error for unknown algorithm' do
    expect do
      HttpSignatures::Algorithm.create(name: 'nope', key: nil)
    end.to raise_error(HttpSignatures::Algorithm::UnknownAlgorithm)
  end
end
