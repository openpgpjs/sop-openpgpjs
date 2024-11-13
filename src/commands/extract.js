const fs = require('fs');
const process = require('process');
const utils = require('../utils');
const { BAD_DATA } = require('../errorCodes');

const extract = async (armor) => {
  const [privateKey] = await utils.load_keys('/dev/stdin');

  try {
    const pubKey = privateKey.toPublic();
    if (!armor) {
      fs.writeSync(1, pubKey.toPacketlist().write());
      return;
    }
    process.stdout.write(pubKey.armor());
  } catch (e) {
    console.error(e.message);
    return process.exit(BAD_DATA);
  }
};

module.exports = extract;
