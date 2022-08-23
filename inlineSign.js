/*global process*/

const openpgp = require('openpgp');
const utils = require('./utils');

const inlineSign = async (certfile, as, armor) => {
  const data = utils.read_stdin();

  const fn = as === 'clearsigned' ? 'createCleartextMessage' : 'createMessage';
  const message = await openpgp[fn](
    as === 'binary' ?
      { binary: data } :
      { text: data.toString('utf8') }
  );
  const options = {
    message,
    signingKeys: await utils.load_keys(certfile),
    format: armor ? 'armored' : 'binary'
  };

  openpgp.sign(options).then(async (signature) => {
    process.stdout.write(signature);
  });
};

module.exports = inlineSign;
