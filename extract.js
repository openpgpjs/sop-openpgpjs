const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');

const extract = async (armor, certfile) => {
    const buf = fs.readFileSync(certfile);
    let readKey = await openpgp.key.read(buf);
    if (!readKey.keys[0]) {
      readKey = await openpgp.key.readArmored(buf);
    }
    const cert = readKey.keys[0];
    const pubKey = cert.toPublic();
    if (!armor) {
        fs.writeSync(1, pubKey.toPacketlist().write());
        return;
    }
    process.stdout.write(pubKey.armor());
}


module.exports = extract;
