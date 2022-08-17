const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');
const utils = require('./utils');

const NO_SIGNATURE = 3;
const BAD_DATA = 41;

const verify = async (signature, certfile) => {

  const certs = await utils.load_certs(certfile);
  const cert = certs[0];
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

  const data = utils.read_stdin();

  let options = {
    message: await openpgp.createMessage({ text: data.toString('utf8') }),
    verificationKeys: [cert],
    signature: sig,
  };

  openpgp.verify(options).then(async (sig) => {
    let count = 0;
    for (let s of sig.signatures) {
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
        const signKey = await cert.getSigningKey(s.keyId, null);
        console.log(timestamp
                    + ' ' + signKey.getFingerprint()
                    + ' ' + cert.getFingerprint());
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
