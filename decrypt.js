const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');

const CANNOT_DECRYPT = 29;

const decrypt = async (withPassword, sessionKeyOut, withSessionKey, verifyWith, verifyOut, certfile) => {
  const encrypted = fs.readFileSync(0);
  let message;
  try {
    message = await openpgp.message.read(encrypted);
  } catch (e) {
    message = await openpgp.message.readArmored(encrypted);
  }

  if (!withPassword && !withSessionKey && !certfile) {
    throw new Error('MISSING_ARG');
  }

  if (withPassword) {
    let options = {
      message: message,
      passwords: withPassword
    }
    openpgp.decrypt(options).then( (clearText) => {
      process.stdout.write(clearText.data);
    }).catch((e) => {
      console.error(e);
      return process.exit(CANNOT_DECRYPT);
     });
    return;
  }

  if (withSessionKey) {
    let sessionBuf = fs.readFileSync(withSessionKey);
    const sessionKey = {
      data: sessionBuf,
      algorithm: 'aes256'
    };
    let options = {
      message: message,
      sessionKeys: sessionKey
    }
    openpgp.decrypt(options).then(async (clearText) => {
      process.stdout.write(clearText.data);
    }).catch((e) => {
      console.error(e);
      return process.exit(CANNOT_DECRYPT);
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
  let options = {
    message: message,
    privateKeys: [cert]
  };

  let verifyKey;
  if (verifyWith) {
    const verifyBuf = fs.readFileSync(verifyWith);
    verifyKey = await openpgp.key.read(verifyBuf);
    if (!verifyKey.keys[0]) {
      verifyKey =  await openpgp.key.readArmored(verifyBuf);
    }
    options.publicKeys = verifyKey.keys[0];
  }

  openpgp.decrypt(options).then( async (clearText) => {
    process.stdout.write(clearText.data);
    if (verifyOut && clearText.signatures[0].valid) {
      const today = Date.now();
      const signKey = await  verifyKey.keys[0].getSigningKey();
      fs.writeFileSync(verifyOut, today + ' ' + signKey.getFingerprint() + ' ' + verifyKey.keys[0].primaryKey.getFingerprint());
    }
  }).catch((e) => {
    console.error(e);
    return process.exit(CANNOT_DECRYPT);
  });

  if (sessionKeyOut) {
    openpgp.decryptSessionKeys({
      message: message,
      privateKeys: [cert]
    }).then( (decryptedSessionKeys) => {
      fs.writeFileSync(sessionKeyOut, decryptedSessionKeys[0].data);
    }).catch((e) => {
      console.error(e);
      return process.exit(CANNOT_DECRYPT);
    });;
  }
};

module.exports = decrypt;
