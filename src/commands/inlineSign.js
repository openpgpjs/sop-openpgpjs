const openpgp = require('../initOpenpgp');
const utils = require('../utils');
const { KEY_CANNOT_SIGN, KEY_IS_PROTECTED } = require('../errorCodes');

const inlineSign = async (keyfiles, withKeyPassword, as, armor) => {
  const data = await utils.readStdin();

  const fn = as === 'clearsigned' ? 'createCleartextMessage' : 'createMessage';
  const message = await openpgp[fn](
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
    }))).catch((e) => {
      utils.logError(e);
      process.exit(KEY_IS_PROTECTED);
    });
  }
  const options = {
    message,
    signingKeys,
    format: armor ? 'armored' : 'binary'
  };

  openpgp.sign(options).then(async (signature) => {
    process.stdout.write(signature);
  }).catch((e) => {
    utils.logError(e);
    return process.exit(KEY_CANNOT_SIGN);
  });
};

module.exports = inlineSign;
