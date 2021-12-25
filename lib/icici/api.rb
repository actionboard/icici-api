# frozen_string_literal: true
require 'securerandom'
require 'base64'
require 'open_ssl'
require 'http_party'
require_relative 'api/version'

module Icici
  module Api
    BASE_URI = 'https://apibankingonesandbox.icicibank.com'.freeze
    URN       = ENV['URN']
    AGGR_NAME = ENV['AGGR_NAME']
    AGGR_ID   = ENV['AGGR_ID']
    APIKEY    = ENV['API_KEY']

    def registration_status(corp_id, user_id)
      url = "#{BASE_URI}/api/Corporate/CIB/v1/Registration"
      make_request(url, {
        "AGGRNAME": AGGR_NAME,
        "AGGRID":   AGGR_ID,
        "CORPID":   corp_id,
        "USERID":   user_id,
        "URN":      urn,
      })
    end

    private

    def make_request(url, payload)
      headers  = {
        "content-type": "application/json",
        apikey:         APIKEY,
      }
      key, iv  = [SecureRandom.hex(8), SecureRandom.hex(8)]
      enc_data = encipher_data(payload.to_json, key, iv)
      body     = {
        "requestId":            SecureRandom.hex,
        "service":              "service",
        "encryptedKey":         encrypt(key),
        "encryptedData":        enc_data,
        "oaepHashingAlgorithm": "NONE",
        "iv":                   ""
      }.to_json
      response = HTTParty.post(url,
                               method:  :post,
                               body:    body,
                               headers: headers)
      response = JSON.parse(response)
      if response['success'].to_s == 'false'
        puts response
      else
        key  = decrypt(response['encryptedKey'])
        data = decipher_data(Base64.strict_decode64(response['encryptedData']), key)
        puts data
        data
      end
    end

    def encrypt(payload)
      cert       = OpenSSL::X509::Certificate.new(ENV['ICICI_BANK_PUBLIC_CERITIFICATE'])
      public_key = cert.public_key
      Base64.strict_encode64(public_key.public_encrypt(payload))
    end

    def decrypt(payload)
      private_key = OpenSSL::PKey::RSA.new(ENV['PRIVATE_CERTIFICATE'])
      private_key.private_decrypt(Base64.decode64(payload))
    end

    def encipher_data(data, key, iv)
      cipher = OpenSSL::Cipher::AES.new(128, :CBC)
      cipher.encrypt
      cipher.key = key
      cipher.iv  = iv
      aes        = cipher.update(iv + data)
      aes << cipher.final
      Base64.strict_encode64(aes)
    end

    def decipher_data(encrypted, key)
      decipher = OpenSSL::Cipher::AES.new(128, :CBC)
      decipher.decrypt
      decipher.key = key
      decipher.iv  = encrypted[0..15]
      aes          = decipher.update(encrypted[16..-1])
      aes << decipher.final
      JSON.parse(aes)
    end

  end
end
