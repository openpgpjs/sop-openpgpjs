const openpgp = require('../initOpenpgp');
const utils = require('../utils');
const { KEY_CANNOT_SIGN } = require('../errorCodes');

const sign = async (keyfiles, withKeyPassword, as, armor) => {
  const data = await utils.readStdin();
  const message = await openpgp.createMessage(
    as === 'binary' ?
      { binary: data } :
      { text: data.toString('utf8') }
  );

  let signingKeys = await utils.loadKeys(...keyfiles);
  if (withKeyPassword) {
    const keyPassword = utils.readFile(withKeyPassword).toString('utf8');
    signingKeys = await Promise.all(signingKeys.map(privateKey => openpgp.decryptKey({
      privateKey,
      passphrase: [keyPassword, keyPassword.trimEnd()]
    })));
  }

  const options = {
    message,
    signingKeys,
    format: 'armored',
    detached: true,
    format: armor ? 'armored' : 'binary'
  };

  openpgp.sign(options).then(async (signature) => {
    process.stdout.write(signature);
  }).catch((e) => {
    console.error(e.message);
    return process.exit(KEY_CANNOT_SIGN);
  });
};

module.exports = sign;
