const openpgp = require('../initOpenpgp');
const process = require('process');
const utils = require('../utils');
const { BAD_DATA } = require('../errorCodes');

const generateKey = async (withKeyPassword, armor, userids, profileOptions) => {
  let passphrase;
  if (withKeyPassword) {
    passphrase = utils.readFile(withKeyPassword).toString('utf8').trimEnd();
  }
  const options = {
    ...profileOptions,
    passphrase,
    userIDs: userids.map((userid) => ({
      name: userid
    })),
    format: armor ? 'armored' : 'binary'
  };
  openpgp.generateKey(options).then(async (key) => {
    process.stdout.write(key.privateKey);
  }).catch((e) => {
    utils.logError(e);
    return process.exit(BAD_DATA);
  });
};

module.exports = generateKey;
