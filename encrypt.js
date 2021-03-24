const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');
const utils = require('./utils');

const CERT_CANNOT_ENCRYPT = 17;

const encrypt = async (withPassword, signWith, certfile) => {
  const data = fs.readFileSync(0, 'utf-8');
  if (withPassword) {
    let options = {
      message: openpgp.message.fromText(data),
      passwords: withPassword
    }
    openpgp.encrypt(options).then( (ciphertext) => {
      process.stdout.write(ciphertext.data);
    });
    return;
  }

  let readKey = await utils.load_certs(certfile);
  const cert = readKey.keys[0];
  const aeadSupported = await openpgp.key.isAeadSupported([cert]);
  if (aeadSupported) {
    openpgp.config.aead_protect = true;
  }
  let options = {
    message: openpgp.message.fromText(data),
    publicKeys: cert,
    armor: true
  };
  if (signWith) {
    let signKey = utils.load_keys(signWith);
    options.privateKeys = signKey.keys[0];
  }

  openpgp.encrypt(options).then( (ciphertext) => {
//    encrypted = ciphertext.message.packets.write(); // get raw encrypted packets as Uint8Array
    process.stdout.write(ciphertext.data);
  }).catch((e) => {
    console.error(e);
    return process.exit(CERT_CANNOT_ENCRYPT);
  });
};

module.exports = encrypt;
