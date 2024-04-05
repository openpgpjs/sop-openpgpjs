const openpgp = require('../initOpenpgp');
const fs = require('fs');
const process = require('process');
const utils = require('../utils');
const { CERT_CANNOT_ENCRYPT } = require('../errorCodes');

const encrypt = async (withPassword, signWith, withKeyPassword, certfiles, profileOptions) => {
  const data = await utils.read_stdin();
  if (withPassword) {
    const password = fs.readFileSync(withPassword);
    const options = {
      ...profileOptions,
      message: await openpgp.createMessage({ text: data.toString('utf8') }),
      passwords: password
    };
    openpgp.encrypt(options).then((ciphertext) => {
      process.stdout.write(ciphertext);
    });
    return;
  }

  const options = {
    ...profileOptions,
    message: await openpgp.createMessage({ text: data.toString('utf8') }),
    encryptionKeys: await utils.load_certs(...certfiles),
    format: 'armored'
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
    console.error(e);
    return process.exit(CERT_CANNOT_ENCRYPT);
  });
};

module.exports = encrypt;
