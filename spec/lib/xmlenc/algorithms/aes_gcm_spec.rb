require 'spec_helper'

describe Xmlenc::Algorithms::AESGCM do
  let(:key) { %w(106572feb0d8e5e798a8e61f155a5bb1).pack('H*') }
  let(:iv) { %w(6913b1dd8d10746703989b97).pack('H*') }
  let(:auth_tag) { %w(ad45a2d1e5aac587161089311703c344).pack('H*') }
  let(:auth_data) { "" }
  let(:cipher_value) { Base64.decode64 "aROx3Y0QdGcDmJuXfXsSM0bfFgVXpFulh7Q6jvo5z90oAWhEnt4RjtiffwtH\nBod9d6dPfADL2cxb+OxwreWs1pcjCyO2fVHecPMlD7tNihNItblUBKCAkzMN\n0EskqfwdYQDpozVcdZHzJKVlE0k3NsCQbV4fRo9nXxw3lwGktQbcMhcxzLmA\nd+97raLfe5U152szRHCjwzIEqWEJM1EiDMzi7+f9OZ+a8+JM4eHBuErtFirG\n01IZCUb2ag==\n" }
  let(:data) { "<CreditCard Currency=\"USD\" Limit=\"5,000\">\r\n    <Number>4019 2445 0277 5567</Number>\r\n    <Issuer>Bank of the Internet</Issuer>\r\n    <Expiration Time=\"04/02\"/>\r\n  </CreditCard>" }
  subject { described_class.new(128).setup(key, auth_tag) }

  describe 'encrypt' do
    it 'encrypts the data' do
      allow(subject).to receive(:iv).and_return(iv)
      result_cipher_value, result_auth_tag = subject.encrypt(data)
      expect(result_auth_tag).to be == auth_tag
      expect(result_cipher_value).to be == cipher_value
    end
  end

  describe 'decrypt' do
    it 'decrypts the cipher_value' do
      expect(subject.decrypt(cipher_value)).to be == data
    end
  end
end
