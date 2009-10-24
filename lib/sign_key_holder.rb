# Manages the on-disk private signing key.
# Author:: Victor Costan
# Copyright:: Copyright (C) 2009 Zergling.Net
# License:: MIT

require 'openssl'


# Contains the authentication proxy's signing key.
class SignKeyHolder
  # The authentication proxy's signing key.
  #
  # Conforms to the OpenSSL::PKey::PKey interface.
  attr_reader :key

  def initialize
    @key = read_key
    unless @key
      @key = generate_key
      write_key
    end
  end
  
  # Erases the key from the filesystem.
  def remove_key
    File.unlink key_path
  end
  
  # Reads the signing key from the filesystem.
  def read_key
    return nil unless File.exist?(key_path)
    OpenSSL::PKey::RSA.new File.read(key_path)
  end
  private :read_key
  
  # Writes the signing key to the filesystem.
  def write_key    
    # Create the file if it's not created.
    File.open(key_path, 'w') { |f| f.write "\n" }
    # Only the Web server's user can access the file.
    File.chmod 0600, key_path
    # Now it's safe to deposit the key in the file.
    File.open(key_path, 'w') { |f| f.write @key.to_pem }
  end
  private :write_key
  
  # Generates signing keys, unless they're already generated.
  def generate_key
    OpenSSL::PKey::RSA.generate 2048
  end
  private :generate_key

  # The path to the file storing the signing key. 
  def key_path
    File.join(RAILS_ROOT, 'config', 'signkey.priv')
  end
  private :key_path
end
