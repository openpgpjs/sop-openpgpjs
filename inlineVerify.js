const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');
const utils = require('./utils');

const NO_SIGNATURE = 3;
const BAD_DATA = 41;

const inlineVerify = async (certfile, verificationsOut) => {
  const verificationKeys = await utils.load_certs(certfile);
  const data = utils.read_stdin();
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
        console.error(e);
        return process.exit(BAD_DATA);
      }
    }
  }

  const options = {
    message,
    verificationKeys
  };

  openpgp.verify(options).then(async (sig) => {
    let count = 0;
    let verifications = '';
    for (const s of sig.signatures) {
      let verified;
      try {
        verified = await s.verified;
      } catch (e) {
        console.error(e);
        verified = false;
      }
      if (verified) {
        count++;
        const signature = await s.signature;
        const timestamp = utils.format_date(signature.packets[0].created);
        for (const cert of verificationKeys) {
          const signKey = await cert.getSigningKey(s.keyId, null);
          if (signKey) {
            verifications +=
              timestamp
                + ' ' + signKey.getFingerprint()
                + ' ' + cert.getFingerprint()
                + '\n';
            break;
          }
        }
      }
    }
    if (count == 0) {
      return process.exit(NO_SIGNATURE);
    }
    if (verificationsOut) {
      fs.writeFileSync(verificationsOut, verifications);
    }
    process.stdout.write(sig.data);
  }).catch((e) => {
    console.error(e);
    return process.exit(BAD_DATA);
  });
};

module.exports = inlineVerify;
