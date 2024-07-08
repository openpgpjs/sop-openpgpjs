const DEFAULT_PROFILE = {
  description: 'use default configuration',
  options: {}
};

const PROFILES = {
  encrypt: {
    'default': DEFAULT_PROFILE,
    'crypto-refresh': {
      description: 'use AEAD for password-protected messages',
      options: { config: { aeadProtect: true } }
    }
  },
  'generate-key': {
    'default': DEFAULT_PROFILE,
    'rfc4880bis': {
      description: 'generate RSA keys',
      options: { type: 'rsa' }
    },
    'crypto-refresh': {
      description: 'generate v6 keys with SEIPDv2 feature flag',
      options: { config: { v6Keys: true, aeadProtect: true } }
    }
  }
};

module.exports = PROFILES;
