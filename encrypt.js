const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');
const utils = require('./utils');

const CERT_CANNOT_ENCRYPT = 17;

const encrypt = async (withPassword, signWith, certfile) => {
  const data = utils.read_stdin();
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
    encryptionKeys: await utils.load_certs(certfile),
    format: 'armored',
    config: {
      aeadProtect: true
    }
  };
  if (signWith) {
    options.signingKeys = utils.load_keys(signWith);
  }

  openpgp.encrypt(options).then((ciphertext) => {
    process.stdout.write(ciphertext);
  }).catch((e) => {
    console.error(e);
    return process.exit(CERT_CANNOT_ENCRYPT);
  });
};

module.exports = encrypt;
