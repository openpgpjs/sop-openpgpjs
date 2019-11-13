#!/usr/bin/env node
var openpgp = require('openpgp');
var yargs = require('yargs');


const encrypt = async (cert) => {

  console.log(cert);
  // set the relative web worker path
  await openpgp.initWorker({ path:'openpgp.worker.js' })

  var options, encrypted;

  options = {
    message: openpgp.message.fromBinary(new Uint8Array([0x01, 0x01, 0x01])), // input as Message object
    passwords: ['secret stuff'],                                             // multiple passwords possible
    armor: true
  };

  openpgp.encrypt(options).then( async function(ciphertext) {
//    encrypted = ciphertext.message.packets.write(); // get raw encrypted packets as Uint8Array
    console.log(ciphertext.data);
  });
};


yargs
  .command('encrypt', 'Encrypt...', (yargs) => {
    yargs
      .positional('cert', {
        describe: 'Cert to use for encryption'
      })
  }, (argv) => {
    console.log(argv);
    encrypt(argv._[1]);
  })
  .help()
  .alias('help', 'h')
  .argv;


