const openpgp = require('../initOpenpgp');
const process = require('process');
const utils = require('../utils');

const dearmor = async () => {
  const data = await utils.readStdin();

  try {
    const { data: unarmored } = await openpgp.unarmor(data);
    process.stdout.write(unarmored);
  } catch (e) {
    process.stdout.write(data);
  }
};

module.exports = dearmor;
