const DEFAULT_PROFILE = {
  description: 'use default configuration',
  options: {}
};

const CUSTOM_PROFILES = JSON.parse(process.env.OPENPGPJS_CUSTOM_PROFILES || '{}');

const BUILTIN_PROFILES = {
  encrypt: {
    'default': {
      ...DEFAULT_PROFILE,
      aliases: ['compatibility', 'rfc4880']
    },
    'performance': {
      description: 'use AEAD for password-protected messages',
      options: { config: { aeadProtect: true } },
      aliases: ['security', 'rfc9580']
    }
  },
  'generate-key': {
    'default': DEFAULT_PROFILE,
    'compatibility': {
      description: 'generate v4 keys using RSA',
      options: { type: 'rsa' },
      aliases: ['rfc4880']
    },
    'performance': {
      description: 'generate v6 keys using Ed25519/X25519 with SEIPDv2 feature flag',
      options: { type: 'curve25519', config: { v6Keys: true, aeadProtect: true } },
      aliases: ['rfc9580']
    },
    'security': {
      description: 'generate v6 keys using Ed448/X448 with SEIPDv2 feature flag',
      options: { type: 'curve448', config: { v6Keys: true, aeadProtect: true } }
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

// For each profile, if it has aliases listed in the `aliases` property,
// copy the profile to each of those alias names, with an additional
// property `isAlias: true`, in order to be able to filter those out
// in `sop list-profiles`.
for (const cmd of Object.keys(PROFILES)) {
  for (const profile of Object.values(PROFILES[cmd])) {
    if (profile.aliases) {
      for (const alias of profile.aliases) {
        PROFILES[cmd][alias] = {
          ...profile,
          isAlias: true
        };
      }
    }
  }
}

module.exports = PROFILES;
