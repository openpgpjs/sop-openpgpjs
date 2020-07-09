const openpgp = require('openpgp');
const fs = require('fs');

const sign = async (certfile) => {

  const buf = fs.readFileSync(certfile);
  let readKey;
  readKey = await openpgp.key.read(buf);
  if (!readKey.keys[0]) {
    readKey = await openpgp.key.readArmored(buf);
  }
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
