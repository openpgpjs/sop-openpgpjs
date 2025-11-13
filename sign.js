const openpgp = require('./initOpenpgp');
const fs = require('fs');
const utils = require('./utils');

const KEY_CANNOT_SIGN = 79;

const sign = async (keyfiles, withKeyPassword) => {
  const data = await utils.read_stdin();

  let signingKeys = await utils.load_keys(...keyfiles);
  if (withKeyPassword) {
    signingKeys = await utils.decrypt_keys(signingKeys, withKeyPassword);
  }

  const options = {
    message: await openpgp.createMessage({ text: data.toString('utf8') }),
    signingKeys,
    format: 'armored',
    detached: true
  };

  openpgp.sign(options).then(async (signature) => {
    process.stdout.write(signature);
  }).catch((e) => {
    console.error(e.message);
    return process.exit(KEY_CANNOT_SIGN);
  });
};

module.exports = sign;
