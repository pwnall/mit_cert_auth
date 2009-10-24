# Author:: Victor Costan
# Copyright:: Copyright (C) 2009 Zergling.Net
# License:: MIT

require 'test_helper'
require 'flexmock/test_unit'


class SignatureVerificationTest < ActiveSupport::TestCase
  def setup
    super
    
    @@key ||= OpenSSL::PKey::RSA.generate 512
    @key = @@key
    
    dn = '/C=US/ST=Massachusetts/O=Massachusetts Institute of Technology/' +
         'OU=Client CA v1/CN=Victor Marius Costan/' +
         'emailAddress=costan@MIT.EDU'
    issuer_dn = '/C=US/ST=Massachusetts/O=Massachusetts Institute of ' +
                'Technology/OU=Client CA v1'
                
    @nonce = 'O9eYWU/t1NSb+ZDmfniqizBSeNhVtsnTHS1H3T2FtRc='
    @data = {'dn' => dn, 'issuer_dn' => issuer_dn, 'verify' => 'SUCCESS',
             'serial' => 'D376EC2AE81A03E10743D175CB659F58',
             'nonce' => @nonce, 'valid_from' => (Time.now - 120).utc.to_s,
             'valid_until' => (Time.now + 120).utc.to_s,
             'cipher' => 'DHE-RSA-CAMELLIA256-SHA', 'protocol' => 'TLSv1',
             'ssl_sig' => 'sha1WithRSAEncryption'}        

    flexmock(MitCertAuthProxy).should_receive(:signing_key).
                               and_return(@key.public_key)
  end
  
  def test_valid
    golden_result = { :nonce => @nonce, :name => 'Victor Marius Costan',
                      :email => 'costan@MIT.EDU' }
    
    MitCertAuthProxy.sign_data! @key, @data
    assert_equal golden_result, MitCertAuthProxy.verify_data(@data)
  end
    
  def test_ssl_failure    
    @data['verify'] = 'NONE'
    MitCertAuthProxy.sign_data! @key, @data  
    assert_equal false, MitCertAuthProxy.verify_data(@data)    
  end
  
  def test_certificate_not_yet_valid
    @data['valid_from'] = (Time.now + 15).utc.to_s
    MitCertAuthProxy.sign_data! @key, @data  
    assert_equal false, MitCertAuthProxy.verify_data(@data)
  end
  
  def test_certificate_expired
    @data['valid_until'] = (Time.now - 1).utc.to_s
    MitCertAuthProxy.sign_data! @key, @data  
    assert_equal false, MitCertAuthProxy.verify_data(@data)    
  end

  def test_wrong_dn
    @data['issuer_dn'] = '/C=US/ST=Massachusetts/O=Harvard/OU=Client CA v1'
    MitCertAuthProxy.sign_data! @key, @data  
    assert_equal false, MitCertAuthProxy.verify_data(@data)        
  end
  
  def test_wrong_signature
    MitCertAuthProxy.sign_data! @key, @data  
    @data['serial'] = 'D376EC2AE81A03E10743D175CB659F5'
    assert_equal false, MitCertAuthProxy.verify_data(@data)        
  end
  
  def test_required_keys
    @data.keys.each do |key|
      dup_data = @data.dup
      dup_data.delete key
      MitCertAuthProxy.sign_data! @key, dup_data
      assert_equal false, MitCertAuthProxy.verify_data(dup_data)        
    end
  end
  
  def test_no_signature
    assert_equal false, MitCertAuthProxy.verify_data(@data)        
  end
end
