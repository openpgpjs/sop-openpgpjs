const openpgp = require('../initOpenpgp');
const process = require('process');
const utils = require('../utils');
const { NO_SIGNATURE, BAD_DATA } = require('../errorCodes');

const verify = async (signature, certfiles, withKey, withKeyPassword) => {
  let verificationKeys = await utils.loadKeys(...withKey);
  if (withKeyPassword) {
    // TODO: Only error on key decryption failure if we can't verify
    // the message with another cert or unlocked key.
    verificationKeys = await utils.decryptKeys(verificationKeys, withKeyPassword);
  }
  verificationKeys = verificationKeys.concat(await utils.loadCerts(...certfiles));

  const sigBuf = utils.readFile(signature);
  let sig;
  try {
    sig = await openpgp.readSignature({ binarySignature: sigBuf });
  } catch (e) {
    try {
      sig = await openpgp.readSignature({ armoredSignature: sigBuf.toString('utf8') });
    } catch (e) {
      utils.logError(e);
      return process.exit(BAD_DATA);
    }
  }

  const data = await utils.readStdin();

  const options = {
    message: await openpgp.createMessage({ binary: data }),
    verificationKeys,
    signature: sig,
  };

  openpgp.verify(options).then(async (sig) => {
    const verifications = await utils.getVerifications(sig.signatures, verificationKeys);
    if (verifications === '') {
      return process.exit(NO_SIGNATURE);
    }
    process.stdout.write(verifications);
  }).catch((e) => {
    utils.logError(e);
    return process.exit(BAD_DATA);
  });
};

module.exports = verify;
