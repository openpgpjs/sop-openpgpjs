const openpgp = require('./initOpenpgp');
const fs = require('fs');
const process = require('process');
const utils = require('./utils');
const { NO_SIGNATURE, BAD_DATA } = require('./errorCodes');

const inlineVerify = async (certfiles, verificationsOut) => {
  const verificationKeys = await utils.load_certs(...certfiles);
  const data = await utils.read_stdin();
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
          const signingKey = await cert.getSigningKey(s.keyID, null).catch(() => null);
          if (signingKey) {
            verifications +=
              timestamp
                + ' ' + signingKey.getFingerprint().toUpperCase()
                + ' ' + cert.getFingerprint().toUpperCase()
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
