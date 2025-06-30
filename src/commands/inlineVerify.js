const openpgp = require('../initOpenpgp');
const process = require('process');
const utils = require('../utils');
const { NO_SIGNATURE, BAD_DATA } = require('../errorCodes');

const inlineVerify = async (certfiles, verificationsOut) => {
  const verificationKeys = await utils.loadCerts(...certfiles);
  const data = await utils.readStdin();
  let message;
  try {
    message = await openpgp.readMessage({ binaryMessage: data });
  } catch (e) {
    try {
      message = await openpgp.readMessage({ armoredMessage: data.toString('utf8') });
    } catch (e) {
      try {
        message = await openpgp.readCleartextMessage({ cleartextMessage: data.toString('utf8') });
      } catch (e) {
        utils.logError(e);
        return process.exit(BAD_DATA);
      }
    }
  }

  const options = {
    message,
    verificationKeys,
    format: message instanceof openpgp.CleartextMessage ?
      'text' :
      'binary'
  };

  openpgp.verify(options).then(async (sig) => {
    const verifications = await utils.getVerifications(sig.signatures, verificationKeys);
    if (verifications === '') {
      return process.exit(NO_SIGNATURE);
    }
    if (verificationsOut) {
      utils.writeFile(verificationsOut, verifications);
    }
    process.stdout.write(sig.data);
  }).catch((e) => {
    utils.logError(e);
    return process.exit(BAD_DATA);
  });
};

module.exports = inlineVerify;
