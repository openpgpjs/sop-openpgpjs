const openpgp = require('openpgp');
const utils = require('./utils');

const sign = async (certfile) => {

  const data = utils.read_stdin();

  const options = {
    message: await openpgp.createMessage({ text: data.toString('utf8') }),
    signingKeys: await utils.load_keys(certfile),
    format: 'armored',
    detached: true
  };

  openpgp.sign(options).then(async (signature) => {
    process.stdout.write(signature);
  });
};

module.exports = sign;
