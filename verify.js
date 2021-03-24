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

  const data = fs.readFileSync(0, 'utf-8');

  let options = {
    message: openpgp.message.fromText(data),
    publicKeys: [cert],
    signature: sig,
  };

  openpgp.verify(options).then(async (sig) => {
    if (sig.signatures[0].valid) {
      const today = sig.signatures[0].signature.packets[0].created.toISOString();
      const signKey = await cert.getSigningKey(sig.signatures[0].signature.issuerKeyId, null);
      console.log(today + ' ' + signKey.getFingerprint() + ' ' + cert.primaryKey.getFingerprint());
    } else {
      return process.exit(NO_SIGNATURE);
    }
  }).catch((e) => {
    console.error(e);
    return process.exit(BAD_DATA);
  });
};

module.exports = verify;
