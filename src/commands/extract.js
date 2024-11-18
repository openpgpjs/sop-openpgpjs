const process = require('process');
const utils = require('../utils');
const { BAD_DATA } = require('../errorCodes');

const extract = async (armor) => {
  const [privateKey] = await utils.loadKeys('/dev/stdin');

  try {
    const pubKey = privateKey.toPublic();
    if (!armor) {
      process.stdout.write(pubKey.toPacketlist().write());
      return;
    }
    process.stdout.write(pubKey.armor());
  } catch (e) {
    console.error(e.message);
    return process.exit(BAD_DATA);
  }
};

module.exports = extract;
