const openpgp = require('openpgp');
const fs = require('fs');
const utils = require('./utils');

const sign = async (certfile) => {

  let readKey = await utils.load_keys(certfile);
  const cert = readKey.keys[0];
  const data = fs.readFileSync(0, 'utf-8');

  let options = {
    message: openpgp.message.fromText(data),
    privateKeys: [cert],
    armor: true,
    detached: true
  };

  openpgp.sign(options).then( async (signed) => {
    process.stdout.write(signed.signature);
  });
};

module.exports = sign;
