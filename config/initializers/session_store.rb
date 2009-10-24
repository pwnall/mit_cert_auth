# Be sure to restart your server when you modify this file.

# Your secret key for verifying cookie session data integrity.
# If you change this key, all old sessions will become invalid!
# Make sure the secret is at least 30 characters and all random, 
# no regular words or you'll be exposed to dictionary attacks.
ActionController::Base.session = {
  :key         => '_mit_cert_auth_session',
  :secret      => 'e332cac5c9eb6b81873bcc421c8b1da274fde5ea8ee7b71ea721949f7b6b54c8f002a88edce0e23e1a1b75a2357a27df8f5ea7e8f8be48c0690a5dd6428becd8'
}

# Use the database for sessions instead of the cookie-based default,
# which shouldn't be used to store highly confidential information
# (create the session table with "rake db:sessions:create")
# ActionController::Base.session_store = :active_record_store
