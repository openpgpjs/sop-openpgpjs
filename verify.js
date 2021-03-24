const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');
const utils = require('./utils');

const NO_SIGNATURE = 3;
const BAD_DATA = 41;

const verify = async (signature, certfile) => {

  const buf = fs.readFileSync(certfile);
  let readKey = await utils.load_certs(certfile);
  const cert = readKey.keys[0];
  const sigBuf = fs.readFileSync(signature);
  let sig;
  try {
    sig = await openpgp.signature.read(sigBuf);
  } catch (e) {
    try {
      sig = await openpgp.signature.readArmored(sigBuf);
    } catch (e) {
      console.error(e);
      return process.exit(BAD_DATA);
    }
  }

  const data = utils.read_stdin();

  let options = {
    message: openpgp.message.fromText(data),
    publicKeys: [cert],
    signature: sig,
  };

  openpgp.verify(options).then(async (sig) => {
    let count = 0;
    for (s of sig.signatures) {
      if (s.valid) {
        count += 1;
        const timestamp = s.signature.packets[0].created.toISOString();
        const signKey = await cert.getSigningKey(s.signature.issuerKeyId, null);
        console.log(timestamp
                    + ' ' + signKey.getFingerprint()
                    + ' ' + cert.primaryKey.getFingerprint());
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
