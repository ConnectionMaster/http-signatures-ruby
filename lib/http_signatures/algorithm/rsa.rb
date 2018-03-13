# frozen_string_literal: true

require 'openssl'

module HttpSignatures
  module Algorithm
    class Rsa
      def initialize(digest_name)
        @digest_name = digest_name
        @digest = OpenSSL::Digest.new(digest_name)
      end

      def name
        "rsa-#{@digest_name}"
      end

      def sign(key, data)
        rsa = OpenSSL::PKey::RSA.new(key)
        rsa.sign(@digest, data)
      end
    end
  end
end
