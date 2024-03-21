const openpgp = require('./initOpenpgp');
const fs = require('fs');
const process = require('process');

const BAD_DATA = 41;

const generateKey = async (withKeyPassword, armor, userids) => {
  let passphrase;
  if (withKeyPassword) {
    passphrase = fs.readFileSync(withKeyPassword, 'utf8').trimEnd();
  }
  const options = {
    passphrase,
    userIDs: userids.map((userid) => ({
      name: userid
    })),
    format: armor ? 'armored' : 'binary'
  };
  openpgp.generateKey(options).then(async (key) => {
    process.stdout.write(key.privateKey);
  }).catch((e) => {
    console.error(e);
    return process.exit(BAD_DATA);
  });
};

module.exports = generateKey;
