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
        
    @nonce = 'O9eYWU/t1NSb+ZDmfniqizBSeNhVtsnTHS1H3T2FtRc='
    @data = MitCertAuthProxy.mock_auth_data 'Victor Marius Costan',
                                            'costan@MIT.EDU', @key, @nonce
    @data.delete 'signature'
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
