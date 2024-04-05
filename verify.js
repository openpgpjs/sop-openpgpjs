const openpgp = require('./initOpenpgp');
const fs = require('fs');
const process = require('process');
const utils = require('./utils');
const { NO_SIGNATURE, BAD_DATA } = require('./errorCodes');

const verify = async (signature, certfiles) => {
  const certs = await utils.load_certs(...certfiles);
  const sigBuf = fs.readFileSync(signature);
  let sig;
  try {
    sig = await openpgp.readSignature({ binarySignature: sigBuf });
  } catch (e) {
    try {
      sig = await openpgp.readSignature({ armoredSignature: sigBuf.toString('utf8') });
    } catch (e) {
      console.error(e);
      return process.exit(BAD_DATA);
    }
  }

  const data = await utils.read_stdin();

  const options = {
    message: await openpgp.createMessage({ text: data.toString('utf8') }),
    verificationKeys: certs,
    signature: sig,
  };

  openpgp.verify(options).then(async (sig) => {
    let count = 0;
    for (const s of sig.signatures) {
      let verified;
      try {
        verified = await s.verified;
      } catch (e) {
        console.error(e);
        verified = false;
      }
      if (verified) {
        count += 1;
        const signature = await s.signature;
        const timestamp = utils.format_date(signature.packets[0].created);
        for (const cert of certs) {
          const signingKey = await cert.getSigningKey(s.keyID, null).catch(() => null);
          if (signingKey) {
            console.log(timestamp
                        + ' ' + signingKey.getFingerprint().toUpperCase()
                        + ' ' + cert.getFingerprint().toUpperCase());
            break;
          }
        }
      }
    }

    if (count == 0) {
      return process.exit(NO_SIGNATURE);
    }
  }).catch((e) => {
    console.error(e);
    return process.exit(BAD_DATA);
  });
};

module.exports = verify;
