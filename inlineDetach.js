const openpgp = require('./initOpenpgp');
const fs = require('fs');
const process = require('process');
const utils = require('./utils');

const BAD_DATA = 41;

const inlineDetach = async (signaturesOut, armor) => {
  const data = await utils.read_stdin();
  let message;
  try {
    message = await openpgp.readMessage({ binaryMessage: data });
  } catch (e) {
    try {
      message = await openpgp.readMessage({ armoredMessage: data.toString('utf8') });
    } catch (e) {
      try {
        message = await openpgp.readCleartextMessage({ cleartextMessage: data.toString('utf8') });
      } catch (e) {
        console.error(e);
        return process.exit(BAD_DATA);
      }
    }
  }

  const options = {
    message,
    verificationKeys: []
  };

  openpgp.verify(options).then(async (sig) => {
    const signaturePackets = new openpgp.PacketList();
    for (const s of sig.signatures) {
      const signature = await s.signature;
      signaturePackets.push(signature.packets[0]);
    }
    if (signaturesOut) {
      const signatures = new openpgp.Signature(signaturePackets)[armor ? 'armor' : 'write']();
      fs.writeFileSync(signaturesOut, signatures);
    }
    process.stdout.write(sig.data);
  }).catch((e) => {
    console.error(e);
    return process.exit(BAD_DATA);
  });
};

module.exports = inlineDetach;
