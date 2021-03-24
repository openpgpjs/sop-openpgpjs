const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');
const utils = require('./utils');

const CANNOT_DECRYPT = 29;

const decrypt = async (withPassword, sessionKeyOut, withSessionKey, verifyWith, verifyOut, certfile) => {
  const encrypted = utils.read_stdin();
  let message;
  try {
    message = await openpgp.message.read(encrypted);
  } catch (e) {
    try {
      message = await openpgp.message.readArmored(encrypted);
    } catch (e) {
      console.error(e);
      return process.exit(BAD_DATA);
    }
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

  let readKey = await utils.load_keys(certfile);
  const cert = readKey.keys[0];
  let options = {
    message: message,
    privateKeys: [cert]
  };

  let verifyKey;
  if (verifyWith) {
    verifyKey = await utils.load_certs(verifyWith);
    options.publicKeys = verifyKey.keys[0];
  }

  openpgp.decrypt(options).then( async (clearText) => {
    process.stdout.write(clearText.data);
    if (verifyOut) {
      let count = 0;
      for (s of sig.signatures) {
        if (s.valid) {
        count += 1;
        const timestamp = s.signature.packets[0].created.toISOString();
        const signKey = await verifyKey.getSigningKey(s.signature.issuerKeyId, null);
          fs.writeFileSync(verifyOut,
                           timestamp
                           + ' ' + signKey.getFingerprint()
                           + ' ' + verifyKey.keys[0].primaryKey.getFingerprint());
        }
      }
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
