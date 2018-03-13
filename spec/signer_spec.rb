# frozen_string_literal: true

require 'net/http'

RSpec.describe HttpSignatures::Signer do
  # Use the test request from:
  #  https://tools.ietf.org/html/draft-cavage-http-signatures-09#appendix-C
  EXAMPLE_DATE = 'Sun, 05 Jan 2014 21:31:40 GMT'
  HEADERS = %w[(request-target) host date content-type digest content-length].freeze

  let(:header_list) { HttpSignatures::HeaderList.new(HEADERS) }

  let(:message) do
    Net::HTTP::Post.new(
      '/foo?param=value&pet=dog',
      'Host' => 'example.com',
      'Date' => EXAMPLE_DATE,
      'Digest' => 'SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
      'Content-Type' => 'application/json',
      'Content-Length' => '18'
    )
  end

  let(:authorization_structure_pattern) do
    %r{
      \A
      Signature
      \s
      keyId="[\w-]+",
      algorithm="[\w-]+",
      (?:headers=".*",)?
      signature="[a-zA-Z0-9/+=]+"
      \z
    }x
  end

  let(:signature_structure_pattern) do
    %r{
      \A
      keyId="[\w-]+",
      algorithm="[\w-]+",
      (?:headers=".*",)?
      signature="[a-zA-Z0-9/+=]+"
      \z
    }x
  end

  context 'using hmac-sha256' do
    let(:key) { HttpSignatures::Key.new(id: 'Test', secret: 'sh') }
    let(:algorithm) { HttpSignatures::Algorithm::Hmac.new('sha256') }

    subject(:signer) do
      HttpSignatures::Signer.new(key: key, algorithm: algorithm, header_list: header_list)
    end

    describe '#sign' do
      it 'passes correct signing string to algorithm' do
        expect(algorithm).to receive(:sign).with(
          'sh',
          ['(request-target): post /foo?param=value&pet=dog',
           'host: example.com',
           'date: Sun, 05 Jan 2014 21:31:40 GMT',
           'content-type: application/json',
           'digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
           'content-length: 18'].join("\n")
        ).at_least(:once).and_return('static')
        signer.sign(message)
      end

      it 'returns reference to the mutated input' do
        expect(signer.sign(message)).to eq(message)
      end
    end

    context 'after signing' do
      before { signer.sign(message) }

      it 'has valid Authorization header structure' do
        expect(message['Authorization']).to match(authorization_structure_pattern)
      end

      it 'has valid Signature header structure' do
        expect(message['Signature']).to match(signature_structure_pattern)
      end

      it 'matches expected Authorization header' do
        expected = [
          'Signature keyId="Test"',
          'algorithm="hmac-sha256"',
          'headers="(request-target) host date content-type digest content-length"',
          'signature="cAFOUAMtTZeGDdgR3kCbXXw9eJqN266+LOZrrC6Xe+o="'
        ].join(',')
        expect(message['Authorization']).to eq(expected)
      end

      it 'matches expected Signature header' do
        expected = [
          'keyId="Test"',
          'algorithm="hmac-sha256"',
          'headers="(request-target) host date content-type digest content-length"',
          'signature="cAFOUAMtTZeGDdgR3kCbXXw9eJqN266+LOZrrC6Xe+o="'
        ].join(',')
        expect(message['Signature']).to eq(expected)
      end
    end
  end

  context 'using rsa-sha256' do
    let(:key) { HttpSignatures::Key.new(id: 'Test', secret: File.read('spec/files/test.pem')) }
    let(:algorithm) { HttpSignatures::Algorithm::Rsa.new('sha256') }

    subject(:signer) do
      HttpSignatures::Signer.new(key: key, algorithm: algorithm, header_list: header_list)
    end

    describe '#sign' do
      it 'passes correct signing string to algorithm' do
        expect(algorithm).to receive(:sign).with(
          anything,
          ['(request-target): post /foo?param=value&pet=dog',
           'host: example.com',
           'date: Sun, 05 Jan 2014 21:31:40 GMT',
           'content-type: application/json',
           'digest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=',
           'content-length: 18'].join("\n")
        ).at_least(:once).and_return('static')
        signer.sign(message)
      end

      it 'returns reference to the mutated input' do
        expect(signer.sign(message)).to eq(message)
      end
    end

    context 'after signing' do
      before { signer.sign(message) }

      it 'has valid Authorization header structure' do
        expect(message['Authorization']).to match(authorization_structure_pattern)
      end

      it 'has valid Signature header structure' do
        expect(message['Signature']).to match(signature_structure_pattern)
      end

      it 'matches expected Authorization header' do
        expected = [
          'Signature keyId="Test"',
          'algorithm="rsa-sha256"',
          'headers="(request-target) host date content-type digest content-length"',
          'signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="'
        ].join(',')
        expect(message['Authorization']).to eq(expected)
      end

      it 'matches expected Signature header' do
        expected = [
          'keyId="Test"',
          'algorithm="rsa-sha256"',
          'headers="(request-target) host date content-type digest content-length"',
          'signature="vSdrb+dS3EceC9bcwHSo4MlyKS59iFIrhgYkz8+oVLEEzmYZZvRs8rgOp+63LEM3v+MFHB32NfpB2bEKBIvB1q52LaEUHFv120V01IL+TAD48XaERZFukWgHoBTLMhYS2Gb51gWxpeIq8knRmPnYePbF5MOkR0Zkly4zKH7s1dE="'
        ].join(',')
        expect(message['Signature']).to eq(expected)
      end
    end
  end
end
