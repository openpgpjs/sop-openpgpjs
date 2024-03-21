const openpgp = require('./initOpenpgp');
const fs = require('fs');
const utils = require('./utils');

const inlineSign = async (keyfiles, withKeyPassword, as, armor) => {
  const data = utils.read_stdin();

  const fn = as === 'clearsigned' ? 'createCleartextMessage' : 'createMessage';
  const message = await openpgp[fn](
    as === 'binary' ?
      { binary: data } :
      { text: data.toString('utf8') }
  );
  let signingKeys = await utils.load_keys(...keyfiles);
  if (withKeyPassword) {
    const keyPassword = fs.readFileSync(withKeyPassword, 'utf8');
    signingKeys = await Promise.all(signingKeys.map(privateKey => openpgp.decryptKey({
      privateKey,
      passphrase: [keyPassword, keyPassword.trimEnd()]
    })));
  }
  const options = {
    message,
    signingKeys,
    format: armor ? 'armored' : 'binary'
  };

  openpgp.sign(options).then(async (signature) => {
    process.stdout.write(signature);
  });
};

module.exports = inlineSign;
