/*global Buffer*/

const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');
const utils = require('./utils');

const CANNOT_DECRYPT = 29;
const BAD_DATA = 41;

const decrypt = async (withPassword, sessionKeyOut, withSessionKey, verifyWith, verifyOut, certfile, withKeyPassword) => {
  const encrypted = utils.read_stdin();
  let message;
  try {
    message = await openpgp.readMessage({ binaryMessage: encrypted });
  } catch (e) {
    try {
      message = await openpgp.readMessage({ armoredMessage: encrypted.toString('utf8') });
    } catch (e) {
      console.error(e);
      return process.exit(BAD_DATA);
    }
  }

  if (!withPassword && !withSessionKey && !certfile) {
    throw new Error('MISSING_ARG');
  }

  if (withPassword) {
    const password = fs.readFileSync(withPassword);
    const options = {
      message: message,
      passwords: password
    };
    openpgp.decrypt(options).then((clearText) => {
      process.stdout.write(clearText.data);
    }).catch((e) => {
      console.error(e);
      return process.exit(CANNOT_DECRYPT);
    });
    return;
  }

  if (withSessionKey) {
    const sessionKeyEncoded = fs.readFileSync(withSessionKey, 'utf8');
    const [algo, data] = sessionKeyEncoded.split(':');
    const sessionKey = {
      data: Buffer.from(data, 'hex'),
      algorithm: openpgp.enums.read(openpgp.enums.symmetric, +algo)
    };
    const options = {
      message: message,
      sessionKeys: sessionKey
    };
    openpgp.decrypt(options).then(async (clearText) => {
      process.stdout.write(clearText.data);
    }).catch((e) => {
      console.error(e);
      return process.exit(CANNOT_DECRYPT);
    });
    return;
  }

  let decryptionKeys = await utils.load_keys(certfile);
  if (withKeyPassword) {
    const keyPassword = fs.readFileSync(withKeyPassword, 'utf8');
    decryptionKeys = await Promise.all(decryptionKeys.map(privateKey => openpgp.decryptKey({
      privateKey,
      passphrase: [keyPassword, keyPassword.trimEnd()]
    })));
  }
  const options = {
    message,
    decryptionKeys
  };

  let verificationKeys;
  if (verifyWith) {
    verificationKeys = await utils.load_certs(verifyWith);
    options.verificationKeys = verificationKeys;
  }

  openpgp.decrypt(options).then(async (clearText) => {
    process.stdout.write(clearText.data);
    if (verifyOut) {
      let verifications = '';
      for (const s of clearText.signatures) {
        let verified;
        try {
          verified = await s.verified;
        } catch (e) {
          console.error(e);
          verified = false;
        }
        if (verified) {
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
      fs.writeFileSync(verifyOut, verifications);
    }
  }).catch((e) => {
    console.error(e);
    return process.exit(CANNOT_DECRYPT);
  });

  if (sessionKeyOut) {
    openpgp.decryptSessionKeys({
      message,
      decryptionKeys
    }).then((decryptedSessionKeys) => {
      const { algorithm, data } = decryptedSessionKeys[0];
      const sessionKeyEncoded =
        openpgp.enums.write(openpgp.enums.symmetric, algorithm) +
        ':' + Buffer.from(data).toString('hex').toUpperCase();
      fs.writeFileSync(sessionKeyOut, sessionKeyEncoded);
    }).catch((e) => {
      console.error(e);
      return process.exit(CANNOT_DECRYPT);
    });
  }
};

module.exports = decrypt;
