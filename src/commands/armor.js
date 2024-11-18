const openpgp = require('../initOpenpgp');

const process = require('process');
const utils = require('../utils');
const { BAD_DATA } = require('../errorCodes');

const allPackets = {};
for (const maybePacket of Object.values(openpgp)) {
  if (maybePacket.tag) {
    allPackets[maybePacket.tag] = maybePacket;
  }
}

const armor = async () => {
  let data = await utils.read_stdin();
  try {
    // If the data is already armored, unarmor it first.
    ({ data } = await openpgp.unarmor(data));
  } catch (e) {}
  const packets = await openpgp.PacketList.fromBinary(data, allPackets);
  const type = detectType(packets);
  const emitChecksum = shouldEmitChecksum(packets);
  const armored = openpgp.armor(type, data, undefined, undefined, undefined, emitChecksum);
  process.stdout.write(armored);
};

const detectType = (packets) => {
  switch (packets[0].constructor) {
    case openpgp.SecretKeyPacket:
      return openpgp.enums.armor.privateKey;
    case openpgp.PublicKeyPacket:
      return openpgp.enums.armor.publicKey;
    case openpgp.PublicKeyEncryptedSessionKeyPacket:
    case openpgp.SymEncryptedSessionKeyPacket:
    case openpgp.OnePassSignaturePacket:
      return openpgp.enums.armor.message;
    case openpgp.SignaturePacket:
      return packets.every(packet => packet.constructor === openpgp.SignaturePacket) ?
        openpgp.enums.armor.signature :
        openpgp.enums.armor.message;
    default:
      return process.exit(BAD_DATA);
  }
}

const shouldEmitChecksum = (packets) => {
  // RFC9580 Section 6.1:
  // An ASCII-armored Encrypted Message packet sequence that ends in an v2 SEIPD packet MUST NOT contain a CRC24 footer.
  const trailingPacket = packets[packets.length - 1];
  if (trailingPacket.constructor === openpgp.SymEncryptedIntegrityProtectedDataPacket &&
    trailingPacket.version === 2)
    return false;
  // An ASCII-armored sequence of Signature packets that only includes v6 Signature packets MUST NOT contain a CRC24 footer.
  if (packets.every(packet => packet.constructor === openpgp.SignaturePacket && packet.version === 6))
    return false;
  // An ASCII-armored Transferable Public Key packet sequence of a v6 key MUST NOT contain a CRC24 footer.
  // An ASCII-armored keyring consisting of only version 6 keys MUST NOT contain a CRC24 footer.
  if ((packets[0].constructor === openpgp.PublicKeyPacket ||
    packets[0].constructor === openpgp.SecretKeyPacket) &&
    packets.every(packet => (
      (packet.constructor !== openpgp.PublicKeyPacket &&
      packet.constructor !== openpgp.SecretKeyPacket) ||
      packet.version === 6)))
    return false;
  return true;
}

module.exports = armor;
