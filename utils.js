const openpgp = require('./initOpenpgp');
const fs = require('fs');
const process = require('process');
const streamConsumer = require('node:stream/consumers');

const BAD_DATA = 41;
const KEY_IS_PROTECTED = 67;

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
        console.error(e.message);
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
        console.error(e.message);
        return process.exit(BAD_DATA);
      }
    }

    return keys;
  }))).flat();
};

const decrypt_keys = async (keys, withKeyPassword) => {
  const keyPassword = fs.readFileSync(withKeyPassword, 'utf8');
  try {
    return await Promise.all(keys.map(async privateKey => {
      if (privateKey.isDecrypted()) {
        return privateKey;
      }
      return await openpgp.decryptKey({
        privateKey,
        passphrase: [keyPassword, keyPassword.trimEnd()]
      });
    }));
  } catch (e) {
    console.error(e.message);
    process.exit(KEY_IS_PROTECTED);
  }
};

const read_stdin = () => streamConsumer.buffer(process.stdin);

// Emits a Date as specified in Section 5.9 of the SOP spec.
const format_date = (d) => {
  return d.toISOString().replace(/\.\d{3}/, ''); // ISO 8601 format without milliseconds.
};

module.exports.load_certs = load_certs;
module.exports.load_keys = load_keys;
module.exports.decrypt_keys = decrypt_keys;
module.exports.read_stdin = read_stdin;
module.exports.format_date = format_date;
