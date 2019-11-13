#!/usr/bin/env node
var openpgp = require('openpgp');
var yargs = require('yargs');
var fs = require('fs');

const encrypt = async (cert) => {

  console.log(cert);
  // set the relative web worker path
  await openpgp.initWorker({ path:'openpgp.worker.js' })

  var options, encrypted;

  options = {
    message: openpgp.message.fromBinary(new Uint8Array([0x01, 0x01, 0x01])), // input as Message object
    // passwords: ['secret stuff'],                                             // multiple passwords possible
    publicKeys: cert,
    armor: true
  };

  openpgp.encrypt(options).then( async function(ciphertext) {
//    encrypted = ciphertext.message.packets.write(); // get raw encrypted packets as Uint8Array
    console.log(ciphertext.data);
  });
};


yargs
  .command('encrypt [cert]', 'Encrypt...', (yargs) => {}, async (argv) => {
    console.log(argv);

    const buf = fs.readFileSync(argv.cert);
    const readKey = await openpgp.key.read(buf).catch(e => openpgp.key.readArmored(buf));
    console.log({readKey});
    encrypt(readKey.keys[0]);
  })
  .help()
  .alias('help', 'h')
  .argv;


