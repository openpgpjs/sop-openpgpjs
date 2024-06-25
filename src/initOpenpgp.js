const openpgp = require(process.env.OPENPGPJS_PATH || 'openpgp');

if (process.env.OPENPGPJS_CONFIG) {
  Object.assign(openpgp.config, JSON.parse(process.env.OPENPGPJS_CONFIG));
}

module.exports = openpgp;
