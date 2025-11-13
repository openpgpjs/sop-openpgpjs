const openpgp = require('./initOpenpgp');
const fs = require('fs');
const process = require('process');
const utils = require('./utils');

const CERT_CANNOT_ENCRYPT = 17;

const encrypt = async (withPassword, signWith, withKeyPassword, certfiles) => {
  const data = await utils.read_stdin();
  if (withPassword) {
    const password = fs.readFileSync(withPassword);
    const options = {
      message: await openpgp.createMessage({ text: data.toString('utf8') }),
      passwords: password
    };
    openpgp.encrypt(options).then((ciphertext) => {
      process.stdout.write(ciphertext);
    });
    return;
  }

  const options = {
    message: await openpgp.createMessage({ text: data.toString('utf8') }),
    encryptionKeys: await utils.load_certs(...certfiles),
    format: 'armored'
  };
  if (signWith.length) {
    let signingKeys = await utils.load_keys(...signWith);
    if (withKeyPassword) {
      signingKeys = await utils.decrypt_keys(signingKeys, withKeyPassword);
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
