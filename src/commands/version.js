const openpgp = require('../initOpenpgp');
const process = require('process');

const SOP_VERSION = '~draft-dkg-openpgp-stateless-cli-06';
const SOPV_VERSION = '1.0';

const version = (argv) => {
  if (argv.sopSpec) {
    console.log(SOP_VERSION);
    return;
  }
  if (argv.sopv) {
    console.log(SOPV_VERSION);
    return;
  }
  if (!argv.backend || argv.extended) {
    const package = require('../../package.json');
    console.log(package.name + ' ' + package.version);
  }
  if (argv.backend || argv.extended) {
    console.log(openpgp.config.versionString);
  }
  if (argv.extended) {
    console.log('Running on Node.js ' + process.version);
  }
};

module.exports = version;
