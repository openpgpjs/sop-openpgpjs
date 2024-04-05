const openpgp = require('./initOpenpgp');
const fs = require('fs');
const process = require('process');
const streamConsumer = require('node:stream/consumers');
const { BAD_DATA, UNSUPPORTED_PROFILE } = require('./errorCodes');
const PROFILES = require('./profiles');

const load_certs = async (...filenames) => {
  return (await Promise.all(filenames.map(async filename => {
    const buf = fs.readFileSync(filename);

    let certs;
    try {
      certs = await openpgp.readKeys({ binaryKeys: buf });
    } catch (e) {
      try {
        certs = await openpgp.readKeys({ armoredKeys: buf.toString('utf8') });
      } catch (e) {
        console.error(e);
        return process.exit(BAD_DATA);
      }
    }

    return certs;
  }))).flat();
};

const load_keys = async (...filenames) => {
  return (await Promise.all(filenames.map(async filename => {
    const buf = fs.readFileSync(filename);

    let keys;
    try {
      keys = await openpgp.readPrivateKeys({ binaryKeys: buf });
    } catch (e) {
      try {
        keys = await openpgp.readPrivateKeys({ armoredKeys: buf.toString('utf8') });
      } catch (e) {
        console.error(e);
        return process.exit(BAD_DATA);
      }
    }

    return keys;
  }))).flat();
};

const read_stdin = () => streamConsumer.buffer(process.stdin);

// Emits a Date as specified in Section 5.9 of the SOP spec.
const format_date = (d) => {
  return d.toISOString().replace(/\.\d{3}/, ''); // ISO 8601 format without milliseconds.
};

const getProfileOptions = (subcommand, profileName = 'default') => {
  const profile = PROFILES[subcommand]?.[profileName];
  if (!profile) {
    console.error('no supported profiles');
    return process.exit(UNSUPPORTED_PROFILE);
  }

  return profile.options;
};

module.exports = {
  load_certs,
  load_keys,
  read_stdin,
  format_date,
  getProfileOptions
};
