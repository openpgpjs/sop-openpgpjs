const openpgp = require('openpgp');
const process = require('process');

const BAD_DATA = 41;

const generateKey = async (armor, userids) => {
  let options = {
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
