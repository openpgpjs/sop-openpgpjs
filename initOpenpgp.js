const openpgp = process.env.OPENPGPJS_PATH ? require(process.env.OPENPGPJS_PATH) : require('openpgp');

if (process.env.OPENPGPJS_CONFIG) {
  Object.assign(openpgp.config, JSON.parse(process.env.OPENPGPJS_CONFIG));
}

module.exports = openpgp;
