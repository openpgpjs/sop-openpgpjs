const openpgp = require('./initOpenpgp');
const fs = require('fs');
const process = require('process');
const streamConsumer = require('node:stream/consumers');
const { BAD_DATA, UNSUPPORTED_PROFILE, KEY_IS_PROTECTED } = require('./errorCodes');
const PROFILES = require('./profiles');

const readStdin = () => streamConsumer.buffer(process.stdin);

const readFile = (filename) => {
  if (filename.startsWith('@ENV:')) {
    return Buffer.from(process.env[filename.substr(5)]);
  }
  if (filename.startsWith('@FD:')) {
    return fs.readFileSync(parseInt(filename.substr(4)));
  }
  return fs.readFileSync(filename);
}

const writeFile = (filename, contents) => {
  if (filename.startsWith('@FD:')) {
    return fs.writeFileSync(parseInt(filename.substr(4)), contents);
  }
  return fs.writeFileSync(filename, contents);
}

const loadCerts = async (...filenames) => {
  return (await Promise.all(filenames.map(async filename => {
    const buf = readFile(filename);

    let certs;
    try {
      certs = await openpgp.readKeys({ binaryKeys: buf });
    } catch (e) {
      try {
        certs = await openpgp.readKeys({ armoredKeys: buf.toString('utf8') });
      } catch (e) {
        logError(e);
        return process.exit(BAD_DATA);
      }
    }
    certs.forEach(cert => {
      cert.filename = filename;
    });

    return certs;
  }))).flat();
};

const loadKeys = async (...filenames) => {
  return (await Promise.all(filenames.map(async filename => {
    const buf = readFile(filename);

    let keys;
    try {
      keys = await openpgp.readPrivateKeys({ binaryKeys: buf });
    } catch (e) {
      try {
        keys = await openpgp.readPrivateKeys({ armoredKeys: buf.toString('utf8') });
      } catch (e) {
        logError(e);
        return process.exit(BAD_DATA);
      }
    }

    return keys;
  }))).flat();
};

const decryptKeys = async (keys, withKeyPassword) => {
  const keyPassword = readFile(withKeyPassword).toString('utf8');
  try {
    return await Promise.all(keys.map(async privateKey => {
      if (privateKey.isDecrypted()) {
        return privateKey;
      }
      return await openpgp.decryptKey({
        privateKey,
        passphrase: [keyPassword, keyPassword.trimEnd()]
      });
    }));
  } catch (e) {
    logError(e);
    process.exit(KEY_IS_PROTECTED);
  }
};

// Emits a Date as specified in Section 5.9 of the SOP spec.
const formatDate = (d) => {
  return d.toISOString().replace(/\.\d{3}/, ''); // ISO 8601 format without milliseconds.
};

const getProfileOptions = (subcommand, profileName = 'default') => {
  const profile = PROFILES[subcommand]?.[profileName];
  if (!profile) {
    console.error('unsupported profile');
    return process.exit(UNSUPPORTED_PROFILE);
  }

  return profile.options;
};

const getVerifications = async (signatures, verificationKeys) => {
  let verifications = '';
  for (const s of signatures) {
    let verified;
    try {
      verified = await s.verified;
    } catch (e) {
      logError(e);
      verified = false;
    }
    if (verified) {
      const signature = await s.signature;
      const timestamp = formatDate(signature.packets[0].created);
      const mode = openpgp.enums.read(openpgp.enums.signature, signature.packets[0].signatureType);
      const signers = [];
      let signingKeyFp, signingCertFp;
      for (const cert of verificationKeys) {
        const [signingKey] = await cert.getKeys(s.keyID);
        if (signingKey) {
          signers.push(cert.filename);
          signingKeyFp = signingKey.getFingerprint().toUpperCase();
          signingCertFp = cert.getFingerprint().toUpperCase();
        }
      }
      verifications +=
        timestamp
          + ' ' + signingKeyFp
          + ' ' + signingCertFp
          + ' mode:' + mode
          + ' ' + JSON.stringify({ signers })
          + '\n';
    }
  }
  return verifications;
};

const logError = function(e) {
  if (globalThis.argv.debug) {
    console.error(e);
  } else {
    console.error(e.message);
  }
};

module.exports = {
  readStdin,
  readFile,
  writeFile,
  loadCerts,
  loadKeys,
  decryptKeys,
  formatDate,
  getProfileOptions,
  getVerifications,
  logError
};
