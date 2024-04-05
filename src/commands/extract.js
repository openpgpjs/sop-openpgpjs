const fs = require('fs');
const process = require('process');
const utils = require('../utils');

const extract = async (armor) => {
  const [privateKey] = await utils.load_keys('/dev/stdin');

  const pubKey = privateKey.toPublic();
  if (!armor) {
    fs.writeSync(1, pubKey.toPacketlist().write());
    return;
  }
  process.stdout.write(pubKey.armor());
};

module.exports = extract;
