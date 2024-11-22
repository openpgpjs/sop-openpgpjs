const openpgp = require('../initOpenpgp');
const process = require('process');
const utils = require('../utils');
const { NO_SIGNATURE, BAD_DATA } = require('../errorCodes');

const verify = async (signature, certfiles) => {
  const certs = await utils.loadCerts(...certfiles);
  const sigBuf = utils.readFile(signature);
  let sig;
  try {
    sig = await openpgp.readSignature({ binarySignature: sigBuf });
  } catch (e) {
    try {
      sig = await openpgp.readSignature({ armoredSignature: sigBuf.toString('utf8') });
    } catch (e) {
      console.error(e.message);
      return process.exit(BAD_DATA);
    }
  }

  const data = await utils.readStdin();

  const options = {
    message: await openpgp.createMessage({ binary: data }),
    verificationKeys: certs,
    signature: sig,
  };

  openpgp.verify(options).then(async (sig) => {
    const verifications = await utils.getVerifications(sig.signatures, certs);
    if (verifications === '') {
      return process.exit(NO_SIGNATURE);
    }
    process.stdout.write(verifications);
  }).catch((e) => {
    console.error(e.message);
    return process.exit(BAD_DATA);
  });
};

module.exports = verify;
