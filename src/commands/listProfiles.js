const process = require('process');
const { UNSUPPORTED_PROFILE } = require('../errorCodes');
const PROFILES = require('../profiles');

const listProfiles = (subcommand) => {
  const supportedProfiles = Object.entries(PROFILES[subcommand] || {});
  if (!supportedProfiles.length) {
    console.error('no supported profiles');
    return process.exit(UNSUPPORTED_PROFILE);
  }

  supportedProfiles.forEach(([name, { description, isAlias, aliases }]) => {
    if (!isAlias) {
      const aliasStr = aliases
        ? (aliases.length > 1
          ? ` (aliases: ${aliases.join(', ')})`
          : ` (alias: ${aliases[0]})`)
        : '';
      process.stdout.write(`${name}: ${description}${aliasStr}\n`);
    }
  });
};

module.exports = listProfiles;
