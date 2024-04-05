const process = require('process');
const { UNSUPPORTED_PROFILE } = require('../errorCodes');
const PROFILES = require('../profiles');

const listProfiles = (subcommand) => {
  if (process.env.DISABLE_PROFILES?.toLowerCase() === 'true') {
    return;
  }
  const supportedProfiles = Object.entries(PROFILES[subcommand] || {});
  if (!supportedProfiles.length) {
    console.error('no supported profiles');
    return process.exit(UNSUPPORTED_PROFILE);
  }

  supportedProfiles.forEach(([name, { description }]) => process.stdout.write(`${name}: ${description}\n`));
};

module.exports = listProfiles;
