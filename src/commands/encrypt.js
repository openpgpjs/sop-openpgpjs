const openpgp = require('../initOpenpgp');
const fs = require('fs');
const process = require('process');
const utils = require('../utils');
const { CERT_CANNOT_ENCRYPT } = require('../errorCodes');

const encrypt = async (withPassword, signWith, withKeyPassword, certfiles, as, armor, profileOptions) => {
  const data = await utils.read_stdin();
  const message = await openpgp.createMessage(
    as === 'binary' ?
      { binary: data } :
      { text: data.toString('utf8') }
  );
  if (withPassword) {
    const password = fs.readFileSync(withPassword);
    const options = {
      ...profileOptions,
      message,
      passwords: password,
      format: armor ? 'armored' : 'binary'
    };
    openpgp.encrypt(options).then((ciphertext) => {
      process.stdout.write(ciphertext);
    });
    return;
  }

  const options = {
    ...profileOptions,
    message,
    encryptionKeys: await utils.load_certs(...certfiles),
    format: armor ? 'armored' : 'binary'
  };
  if (signWith.length) {
    let signingKeys = await utils.load_keys(...signWith);
    if (withKeyPassword) {
      const keyPassword = fs.readFileSync(withKeyPassword, 'utf8');
      signingKeys = await Promise.all(signingKeys.map(privateKey => openpgp.decryptKey({
        privateKey,
        passphrase: [keyPassword, keyPassword.trimEnd()]
      })));
    }
    options.signingKeys = signingKeys;
  }

  openpgp.encrypt(options).then((ciphertext) => {
    process.stdout.write(ciphertext);
  }).catch((e) => {
    console.error(e.message);
    return process.exit(CERT_CANNOT_ENCRYPT);
  });
};

module.exports = encrypt;
