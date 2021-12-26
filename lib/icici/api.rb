# frozen_string_literal: true
require 'securerandom'
require 'base64'
require 'openssl'
require 'httparty'
require 'json'
require_relative 'api/version'

module Icici
  module Api
    BASE_URI  = 'https://apibankingonesandbox.icicibank.com'.freeze
    URN       = ENV['URN']
    AGGR_NAME = ENV['AGGR_NAME']
    AGGR_ID   = ENV['AGGR_ID']
    APIKEY    = ENV['API_KEY']

    def self.registration_status(corp_id, user_id)
      url = "#{BASE_URI}/api/Corporate/CIB/v1/Registration"
      make_request(url, {
        "AGGRNAME": AGGR_NAME,
        "AGGRID":   AGGR_ID,
        "CORPID":   corp_id,
        "USERID":   user_id,
        "URN":      URN,
      })
    end

    def self.send_otp(corp_id, user_id, uniq_id)
      payload = {
        AGGRID:   AGGR_ID,
        AGGRNAME: AGGR_NAME,
        CORPID:   corp_id,
        USERID:   user_id,
        UNIQUEID: uniq_id,
        URN:      URN
      }
      make_request("#{BASE_URL}/api/Corporate/CIB/v1/TransactionOTP", payload)
    end

    # Standard Response Format after Decryption:
    # {"RESPONSE"=>"SUCCESS",
    # "STATUS"=>"SUCCESS",
    # "URN"=>"snap",
    # "UNIQUEID"=>"adsfink",
    # "UTRNUMBER"=>"20190628104317"}

    def self.verify_transfer_status(corp_id, user_id, uniq_id)
      payload = {
        AGGRID:   AGGR_ID,
        CORPID:   corp_id,
        USERID:   user_id,
        UNIQUEID: uniq_id,
        URN:      URN,
      }
      make_request("#{BASE_URL}/api/Corporate/CIB/v1/TransactionInquiry", payload)
    end

    # Standard Response Format after decryption:
    #
    #    {"RESPONSE"=>"SUCCESS",
    #     "AGGR_ID"=>"AGGR0082",
    #     "CORP_ID"=>"CIBNEXT",
    #     "USER_ID"=>"CIBTESTING6",
    #     "URN"=>"snap",
    #     "ACCOUNTNO"=>"000405000281",
    #     "DATE"=>"28/06/19 10:11:09",
    #     "EFFECTIVEBAL"=>"1415368242.49",
    #     "CURRENCY"=>"INR"}

    def self.fetch_balance(corp_id, user_id, account_num)
      payload  = {
        CORPID:    corp_id,
        USERID:    user_id,
        AGGRID:    AGGR_ID,
        URN:       URN,
        ACCOUNTNO: account_num
      }
      make_request("#{BASE_URL}/api/Corporate/CIB/v1/BalanceInquiry", payload)
    end

    def self.make_request(url, payload)
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
      puts response.code
      response = JSON.parse(response.body)
      if response['success'].to_s == 'false'
        puts response
      else
        key  = decrypt(response['encryptedKey'])
        data = decipher_data(Base64.strict_decode64(response['encryptedData']), key)
        puts data
        data
      end
    end

    def self.encrypt(payload)
      cert       = OpenSSL::X509::Certificate.new(ENV['ICICI_BANK_PUBLIC_CERITIFICATE'])
      public_key = cert.public_key
      Base64.strict_encode64(public_key.public_encrypt(payload))
    end

    def self.decrypt(payload)
      private_key = OpenSSL::PKey::RSA.new(ENV['PRIVATE_CERTIFICATE'])
      private_key.private_decrypt(Base64.decode64(payload))
    end

    def self.encipher_data(data, key, iv)
      cipher = OpenSSL::Cipher::AES.new(128, :CBC)
      cipher.encrypt
      cipher.key = key
      cipher.iv  = iv
      aes        = cipher.update(iv + data)
      aes << cipher.final
      Base64.strict_encode64(aes)
    end

    def self.decipher_data(encrypted, key)
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
