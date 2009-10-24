# Author:: Victor Costan
# Copyright:: Copyright (C) 2009 Zergling.Net
# License:: MIT

require 'test_helper'
require 'openssl'


class SignKeyHolderTest < ActiveSupport::TestCase
  def setup
    # Monkey-patch the holder so it doesn't overwrite the real signing key.
    SignKeyHolder.class_eval do
      alias_method :_real_key_path, :key_path
      remove_method :key_path
      define_method :key_path do
        File.join RAILS_ROOT, 'tmp', 'signkey.priv'
      end
    end
    
    @holder = SignKeyHolder.new
  end
  
  def teardown
    # Undo the monkey-patch in setup.
    SignKeyHolder.class_eval do
      remove_method :key_path
      alias_method :key_path, :_real_key_path
      remove_method :_real_key_path
    end
  end
  
  def test_key_interface
    assert_operator @holder.key, :kind_of?, OpenSSL::PKey::PKey
  end
  
  def test_persistence
    holder = SignKeyHolder.new
    assert_equal holder.key.inspect, @holder.key.inspect
  end
  
  def test_key_removal
    @holder.remove_key
    holder = SignKeyHolder.new
    assert_not_equal holder.key.inspect, @holder.key.inspect
  end
end
