const openpgp = require('../initOpenpgp');
const process = require('process');
const utils = require('../utils');
const { CERT_CANNOT_ENCRYPT } = require('../errorCodes');

const encrypt = async (withPassword, signWith, withKeyPassword, certfiles, as, armor, profileOptions) => {
  const data = await utils.readStdin();
  const message = await openpgp.createMessage(
    as === 'binary' ?
      { binary: data } :
      { text: data.toString('utf8') }
  );
  if (withPassword) {
    const password = utils.readFile(withPassword);
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
    encryptionKeys: await utils.loadCerts(...certfiles),
    format: armor ? 'armored' : 'binary'
  };
  if (signWith.length) {
    let signingKeys = await utils.loadKeys(...signWith);
    if (withKeyPassword) {
      signingKeys = await utils.decryptKeys(signingKeys, withKeyPassword);
    }
    options.signingKeys = signingKeys;
  }

  openpgp.encrypt(options).then((ciphertext) => {
    process.stdout.write(ciphertext);
  }).catch((e) => {
    utils.logError(e);
    return process.exit(CERT_CANNOT_ENCRYPT);
  });
};

module.exports = encrypt;
