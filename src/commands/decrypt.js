const openpgp = require('../initOpenpgp');
const process = require('process');
const utils = require('../utils');
const { CANNOT_DECRYPT, BAD_DATA, KEY_IS_PROTECTED } = require('../errorCodes');

const decrypt = async (withPassword, sessionKeyOut, withSessionKey, verifyWith, verificationsOut, keyfiles, withKeyPassword) => {
  const encrypted = await utils.readStdin();
  let message;
  try {
    message = await openpgp.readMessage({ binaryMessage: encrypted });
  } catch (e) {
    try {
      message = await openpgp.readMessage({ armoredMessage: encrypted.toString('utf8') });
    } catch (e) {
      utils.logError(e);
      return process.exit(BAD_DATA);
    }
  }

  if (!withPassword && !withSessionKey && !keyfiles.length) {
    throw new Error('MISSING_ARG');
  }

  if (withPassword) {
    const password = utils.readFile(withPassword);
    const options = {
      message: message,
      passwords: password,
      format: 'binary'
    };
    openpgp.decrypt(options).then((clearText) => {
      process.stdout.write(clearText.data);
    }).catch((e) => {
      utils.logError(e);
      return process.exit(CANNOT_DECRYPT);
    });
    return;
  }

  if (withSessionKey) {
    const sessionKeyEncoded = utils.readFile(withSessionKey).toString('utf8');
    const [algo, data] = sessionKeyEncoded.split(':');
    const sessionKey = {
      data: Buffer.from(data, 'hex'),
      algorithm: openpgp.enums.read(openpgp.enums.symmetric, +algo)
    };
    const options = {
      message: message,
      sessionKeys: sessionKey,
      format: 'binary'
    };
    openpgp.decrypt(options).then(async (clearText) => {
      process.stdout.write(clearText.data);
    }).catch((e) => {
      utils.logError(e);
      return process.exit(CANNOT_DECRYPT);
    });
    return;
  }

  let decryptionKeys = await utils.loadKeys(...keyfiles);
  if (withKeyPassword) {
    const keyPassword = utils.readFile(withKeyPassword).toString('utf8');
    decryptionKeys = await Promise.all(decryptionKeys.map(privateKey => openpgp.decryptKey({
      privateKey,
      passphrase: [keyPassword, keyPassword.trimEnd()]
    }))).catch((e) => {
      // TODO: Only error on key decryption failure if we can't decrypt
      // the message with another key (or password or session key).
      utils.logError(e);
      process.exit(KEY_IS_PROTECTED);
    });
  }

  const decryptedSessionKeys = await openpgp.decryptSessionKeys({
    message,
    decryptionKeys
  }).catch((e) => {
    utils.logError(e);
    process.exit(CANNOT_DECRYPT);
  });

  const options = {
    message,
    sessionKeys: decryptedSessionKeys,
    format: 'binary'
  };

  let verificationKeys;
  if (verifyWith.length) {
    verificationKeys = await utils.loadCerts(...verifyWith);
    options.verificationKeys = verificationKeys;
  }

  openpgp.decrypt(options).then(async (clearText) => {
    process.stdout.write(clearText.data);
    if (verificationsOut) {
      const verifications = await utils.getVerifications(clearText.signatures, verificationKeys);
      utils.writeFile(verificationsOut, verifications);
    }

    if (sessionKeyOut) {
      const { algorithm, data } = decryptedSessionKeys[0];
      const sessionKeyEncoded =
        openpgp.enums.write(openpgp.enums.symmetric, algorithm) +
        ':' + Buffer.from(data).toString('hex').toUpperCase();
      utils.writeFile(sessionKeyOut, sessionKeyEncoded);
    }
  }).catch((e) => {
    utils.logError(e);
    process.exit(CANNOT_DECRYPT);
  });
};

module.exports = decrypt;
