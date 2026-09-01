#!/usr/bin/env node

const yargs = require('yargs');
const utils = require('./src/utils');
const encrypt = require('./src/commands/encrypt');
const decrypt = require('./src/commands/decrypt');
const sign = require('./src/commands/sign');
const verify = require('./src/commands/verify');
const inlineSign = require('./src/commands/inlineSign');
const inlineVerify = require('./src/commands/inlineVerify');
const inlineDetach = require('./src/commands/inlineDetach');
const generate = require('./src/commands/generate');
const extract = require('./src/commands/extract');
const armor = require('./src/commands/armor');
const dearmor = require('./src/commands/dearmor');
const listProfiles = require('./src/commands/listProfiles');
const version = require('./src/commands/version');

globalThis.argv = yargs
  .command({
    command: 'encrypt [certfiles..]',
    describe: 'Encrypt a Message',
    builder: {
      profile: {
        describe: 'specify profile to use',
        type: 'string'
      },
      'with-key': {
        describe: 'encrypt with key',
        type: 'string'
      },
      'with-password': {
        describe: 'symmetric encryption',
        type: 'string'
      },
      'sign-with': {
        describe: 'sign with key',
      },
      'with-key-password': {
        describe: 'unlock signing key with the given password file',
        type: 'string'
      },
      as: {
        describe: 'the type of data to encrypt',
        choices: ['binary', 'text'],
        default: 'binary'
      },
      armor: {
        describe: 'armor the output',
        type: 'boolean',
        default: true
      }
    },
    handler: async (argv) => {
      const signWith = utils.toArray(argv.signWith);
      const withKey = utils.toArray(argv.withKey);
      const certfiles = utils.toArray(argv.certfiles);
      const profileOptions = utils.getProfileOptions('encrypt', argv.profile);
      encrypt(withKey, argv.withPassword, signWith, argv.withKeyPassword, certfiles, argv.as, argv.armor, profileOptions);
    }
  })
  .command({
    command: 'decrypt [keyfiles..]',
    describe: 'Decrypt a Message',
    builder: {
      'session-key-out': {
        describe: 'session key of encrypted message',
      },
      'with-session-key': {
        describe: 'decrypt using provided session key',
      },
      'with-password': {
        describe: 'symmetric encryption',
        type: 'string'
      },
      'with-key-password': {
        describe: 'unlock key with the given password file',
        type: 'string'
      },
      'verify-with': {
        describe: 'verify with cert',
        type: 'string'
      },
      'verify-with-key': {
        describe: 'verify with key',
        type: 'string'
      },
      'verifications-out': {
        describe: 'save verifications to file',
        alias: 'verify-out'
      }
    },
    handler: async (argv) => {
      const verifyWith = utils.toArray(argv.verifyWith);
      const verifyWithKey = utils.toArray(argv.verifyWithKey);
      decrypt(argv.withPassword, argv.sessionKeyOut, argv.withSessionKey, verifyWith, verifyWithKey, argv.verificationsOut, argv.keyfiles, argv.withKeyPassword);
    }
  })
  .command({
    command: 'sign <keyfiles..>',
    describe: 'Create Detached Signatures',
    builder: {
      'with-key-password': {
        describe: 'unlock key with the given password file',
        type: 'string'
      },
      as: {
        describe: 'the type of data to sign',
        choices: ['binary', 'text'],
        default: 'binary'
      },
      armor: {
        describe: 'armor the output',
        type: 'boolean',
        default: true
      }
    },
    handler: async (argv) => { sign(argv.keyfiles, argv.withKeyPassword, argv.as, argv.armor); }
  })
  .command({
    command: 'verify <signature> [certfiles..]',
    describe: 'Verify Detached Signatures',
    builder: {
      'with-key': {
        describe: 'verify with key',
        type: 'string'
      },
      'with-key-password': {
        describe: 'unlock keys with the given password file',
        type: 'string'
      }
    },
    handler: async (argv) => {
      const withKey = utils.toArray(argv.withKey);
      const certfiles = utils.toArray(argv.certfiles);
      verify(argv.signature, certfiles, withKey, argv.withKeyPassword);
    }
  })
  .command({
    command: 'inline-sign <keyfiles..>',
    describe: 'Create an Inline-Signed Message',
    builder: {
      'with-key-password': {
        describe: 'unlock key with the given password file',
        type: 'string'
      },
      as: {
        describe: 'the type of data to sign',
        choices: ['binary', 'text', 'clearsigned'],
        default: 'binary'
      },
      armor: {
        describe: 'armor the output',
        type: 'boolean',
        default: true
      }
    },
    handler: async (argv) => { inlineSign(argv.keyfiles, argv.withKeyPassword, argv.as, argv.armor); }
  })
  .command({
    command: 'inline-verify [certfiles..]',
    describe: 'Verify an Inline-Signed Message',
    builder: {
      'with-key': {
        describe: 'verify with key',
        type: 'string'
      },
      'with-key-password': {
        describe: 'unlock keys with the given password file',
        type: 'string'
      },
      'verifications-out': {
        describe: 'save verifications to file',
      }
    },
    handler: async (argv) => {
      const withKey = utils.toArray(argv.withKey);
      const certfiles = utils.toArray(argv.certfiles);
      inlineVerify(certfiles, withKey, argv.withKeyPassword, argv.verificationsOut);
    }
  })
  .command({
    command: 'inline-detach',
    describe: 'Split Signatures from an Inline-Signed Message',
    builder: {
      'signatures-out': {
        describe: 'save signatures to file',
      },
      armor: {
        describe: 'armor the signatures',
        type: 'boolean'
      }
    },
    handler: async (argv) => {
      const armor = argv.armor != false;
      inlineDetach(argv.signaturesOut, armor);
    }
  })
  .command({
    command: 'extract-cert',
    describe: 'Extract a Certificate from a Secret Key',
    builder: {
      armor: {
        describe: 'armor the output',
        type: 'boolean'
      }
    },
    handler: async (argv) => {
      const armor = argv.armor != false;
      extract(armor);
    }
  })
  .command({
    command: 'generate-key [userids..]',
    describe: 'Generate a Secret Key',
    builder: {
      profile: {
        describe: 'specify profile to use',
        type: 'string'
      },
      'with-key-password': {
        describe: 'lock key with the given password file',
        type: 'string'
      },
      armor: {
        describe: 'armor the output',
        type: 'boolean'
      },
      userids: {
        describe: 'some user ids',
        type: 'string'
      }
    },
    handler: async (argv) => {
      const armor = argv.armor != false;
      const userids = argv.userids || [];
      const profileOptions = utils.getProfileOptions('generate-key', argv.profile);
      generate(argv.withKeyPassword, armor, userids, profileOptions);
    }
  })
  .command({
    command: 'armor',
    describe: 'Convert Binary to ASCII',
    handler: armor
  })
  .command({
    command: 'dearmor',
    describe: 'Convert ASCII to Binary',
    handler: dearmor
  })
  .command({
    command: 'list-profiles <subcommand>',
    describe: 'List custom profiles supported by the given subcommand',
    handler: async (argv) => {
      listProfiles(argv.subcommand);
    }
  })
  .command({
    command: 'version',
    describe: 'Version Information',
    builder: {
      backend: {
        describe: 'display OpenPGP.js version',
        type: 'boolean'
      },
      extended: {
        describe: 'display extended version information',
        type: 'boolean'
      },
      'sop-spec': {
        describe: 'display supported sop specification version',
        type: 'boolean'
      },
      sopv: {
        describe: 'display supported sopv specification version',
        type: 'boolean'
      }
    },
    handler: version
  })
  .version(false) // Disable --version option as we have our own version command.
  .help()
  .alias('help', 'h')
  .option('debug', {
    describe: 'Enable more detailed error reporting',
    type: 'boolean'
  })
  .demandCommand(1)
  .strict()
  .argv;
