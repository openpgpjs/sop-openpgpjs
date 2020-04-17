const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');

const CERT_CANNOT_ENCRYPT = 17;

const encrypt = async (withPassword, signWith, certfile) => {
  const data = fs.readFileSync(0, 'utf-8');
  if (withPassword) {
    let options = {
      message: openpgp.message.fromText(data),
      passwords: withPassword
    }
    openpgp.encrypt(options).then( (ciphertext) => {
      console.log(ciphertext.data);
    });
    return;
  }
  const buf = fs.readFileSync(certfile);
  let readKey;
  readKey = await openpgp.key.read(buf);
  if (!readKey.keys[0]) {
    readKey = await openpgp.key.readArmored(buf);
  }
  const cert = readKey.keys[0];
  const aeadSupported = await openpgp.key.isAeadSupported([cert]);
  if (aeadSupported) {
    openpgp.config.aead_protect = true;
  }
  let options = {
    message: openpgp.message.fromText(data),
    publicKeys: cert,
    armor: true
  };
  if (signWith) {
    const signBuf = fs.readFileSync(signWith);
    let signKey;
    signKey = await openpgp.key.read(signBuf);
    if (!signKey.keys[0]) {
      signKey =  await openpgp.key.readArmored(signBuf);
    }
    options.privateKeys = signKey.keys[0];
  }

  openpgp.encrypt(options).then( (ciphertext) => {
//    encrypted = ciphertext.message.packets.write(); // get raw encrypted packets as Uint8Array
    console.log(ciphertext.data);
  }).catch((e) => {
    console.error(e);
    return process.exit(CERT_CANNOT_ENCRYPT);
  });
};

module.exports = encrypt;
