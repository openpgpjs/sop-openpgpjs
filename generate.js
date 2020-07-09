const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');

const BAD_DATA = 41;

const generateKey = async (armor, userids) => {
  let options = {
    userIds: userids,
  };
  openpgp.generateKey(options).then( async (key) => {
    if (!armor) {
      fs.writeSync(1, key.key.toPacketlist().write());
      return;
    }
    process.stdout.write(key.key.armor());
  }).catch((e) => {
    console.error(e);
    return process.exit(BAD_DATA);
  });
};

module.exports = generateKey;
