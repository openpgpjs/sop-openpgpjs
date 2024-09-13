Implementation of the [Stateless OpenPGP Command Line Interface] for [openpgp-js].


[Stateless OpenPGP Command Line Interface]: https://tools.ietf.org/html/draft-dkg-openpgp-stateless-cli-02
[openpgp-js]: https://openpgpjs.org/

## Install, build and run

Install the dependencies and build the binary (Node.js and npm required):

```sh
npm i
```

And then run it:
```sh
./sopenpgpjs <command>
```

When developing, you can run the tests with

```sh
npm run build
npm test
```

## Run with custom OpenPGP.js library

To run `sop-openpgpjs` using an OpenPGP.js version different than the bundled one, you can set the `OPENPGPJS_PATH` environment variable:
```sh
OPENPGPJS_PATH='../path-to-custom-openpgpjs-lib' ./sopenpgpjs <command>
```
