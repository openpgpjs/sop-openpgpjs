const openpgp = require('./initOpenpgp');
const fs = require('fs');
const utils = require('./utils');

const KEY_CANNOT_SIGN = 79;

const inlineSign = async (keyfiles, withKeyPassword, as, armor) => {
  const data = await utils.read_stdin();

  const fn = as === 'clearsigned' ? 'createCleartextMessage' : 'createMessage';
  const message = await openpgp[fn](
    as === 'binary' ?
      { binary: data } :
      { text: data.toString('utf8') }
  );
  let signingKeys = await utils.load_keys(...keyfiles);
  if (withKeyPassword) {
    signingKeys = await utils.decrypt_keys(signingKeys, withKeyPassword);
  }
  const options = {
    message,
    signingKeys,
    format: armor ? 'armored' : 'binary'
  };

  openpgp.sign(options).then(async (signature) => {
    process.stdout.write(signature);
  }).catch((e) => {
    console.error(e.message);
    return process.exit(KEY_CANNOT_SIGN);
  });
};

module.exports = inlineSign;
