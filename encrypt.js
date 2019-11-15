const openpgp = require('openpgp');
const fs = require('fs');

const encrypt = async (certfile) => {

  const buf = fs.readFileSync(certfile);
  const readKey = await openpgp.key.read(buf).catch(e => openpgp.key.readArmored(buf));
  const cert = readKey.keys[0];
  const data = fs.readFileSync(0, 'utf-8');

  // set the relative web worker path
  await openpgp.initWorker({ path:'openpgp.worker.js' })

  let options = {
    message: openpgp.message.fromText(data),
    publicKeys: cert,
    armor: true
  };

  openpgp.encrypt(options).then( async (ciphertext) => {
//    encrypted = ciphertext.message.packets.write(); // get raw encrypted packets as Uint8Array
    console.log(ciphertext.data);
  });
};

module.exports = encrypt;
