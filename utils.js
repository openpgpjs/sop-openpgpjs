const openpgp = require('openpgp');
const fs = require('fs');
const process = require('process');

const BAD_DATA = 41;

const load_certs = async (filename) => {
  const buf = fs.readFileSync(filename);

  let certs;
  try {
    certs = await openpgp.readKeys({ binaryKeys: buf });
  } catch (e) {
    try {
      certs = await openpgp.readKeys({ armoredKeys: buf.toString('utf8') });
    } catch (e) {
      console.error(e);
      return process.exit(BAD_DATA);
    }
  }

  return certs;
};

const load_keys = async (filename) => {
  const buf = fs.readFileSync(filename);

  let keys;
  try {
    keys = await openpgp.readPrivateKeys({ binaryKeys: buf });
  } catch (e) {
    try {
      keys = await openpgp.readPrivateKeys({ armoredKeys: buf.toString('utf8') });
    } catch (e) {
      console.error(e);
      return process.exit(BAD_DATA);
    }
  }

  return keys;
};

const read_stdin = () => {
  // Using the file descriptor 0 is unreliable, because EAGAIN is
  // not handled.  Using '/dev/stdin' works better, but will not
  // work on non-posixly systems.
  return fs.readFileSync('/dev/stdin');
};

// Emits a Date as specified in Section 5.9 of the SOP spec.
const format_date = (d) => {
  return d.toISOString().replace(/\.\d{3}/, ''); // ISO 8601 format without milliseconds.
};

module.exports.load_certs = load_certs;
module.exports.load_keys = load_keys;
module.exports.read_stdin = read_stdin;
module.exports.format_date = format_date;
