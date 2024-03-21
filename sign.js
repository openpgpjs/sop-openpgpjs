const openpgp = require('./initOpenpgp');
const fs = require('fs');
const utils = require('./utils');

const sign = async (keyfiles, withKeyPassword) => {
  const data = await utils.read_stdin();

  let signingKeys = await utils.load_keys(...keyfiles);
  if (withKeyPassword) {
    const keyPassword = fs.readFileSync(withKeyPassword, 'utf8');
    signingKeys = await Promise.all(signingKeys.map(privateKey => openpgp.decryptKey({
      privateKey,
      passphrase: [keyPassword, keyPassword.trimEnd()]
    })));
  }

  const options = {
    message: await openpgp.createMessage({ text: data.toString('utf8') }),
    signingKeys,
    format: 'armored',
    detached: true
  };

  openpgp.sign(options).then(async (signature) => {
    process.stdout.write(signature);
  });
};

module.exports = sign;
