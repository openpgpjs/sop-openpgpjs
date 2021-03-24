const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');
const utils = require('./utils');

const extract = async (armor, certfile) => {
    let readKey = await utils.load_keys(certfile);
    const cert = readKey.keys[0];
    const pubKey = cert.toPublic();
    if (!armor) {
        fs.writeSync(1, pubKey.toPacketlist().write());
        return;
    }
    process.stdout.write(pubKey.armor());
}


module.exports = extract;
