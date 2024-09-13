const DEFAULT_PROFILE = {
  description: 'use default configuration',
  options: {}
};

const CUSTOM_PROFILES = JSON.parse(process.env.OPENPGPJS_CUSTOM_PROFILES || '{}');

const BUILTIN_PROFILES = {
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

const mergeProfiles = (profiles1, profiles2) => {
  const merged = {};
  const commands = new Set(Object.keys(profiles1).concat(Object.keys(profiles2)));
  for (const cmd of commands) {
    merged[cmd] = { ...(profiles1?.[cmd] || {}), ...(profiles2?.[cmd] || {}) };
  }
  return merged;
};

const PROFILES = mergeProfiles(BUILTIN_PROFILES, CUSTOM_PROFILES);

module.exports = PROFILES;
