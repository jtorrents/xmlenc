require 'xmlenc/version'
require 'openssl'
require 'base64'
require 'nokogiri'

module Xmlenc
  NAMESPACES = {
      xenc: 'http://www.w3.org/2001/04/xmlenc#',
      ds:   'http://www.w3.org/2000/09/xmldsig#'
  }

  class UnsupportedError < StandardError
  end

  module Algorithms
    autoload :Rsa15, 'xmlenc/algorithms/rsa_15'
    autoload :RsaOaepMgf1p, 'xmlenc/algorithms/rsa_oaep_mgf1p'
    autoload :DES3CBC, 'xmlenc/algorithms/des3_cbc'
    autoload :AESCBC, 'xmlenc/algorithms/aes_cbc'
  end

  autoload :EncryptedDocument, 'xmlenc/encrypted_document'
  autoload :EncryptedData, 'xmlenc/encrypted_data'
  autoload :EncryptedKey, 'xmlenc/encrypted_key'
end