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

## Load custom profiles

To load additional profiles (possibly relevant when testing a custom built of OpenPGP.js), you can set the `OPENPGPJS_CUSTOM_PROFILES` environment variable to point to a JSON string declaring an object of the form:
```ts
{
  [targetCommandName: string]: {
    [profileName: string]: {
      description: string,
      options: object
    }
  }
}
```
Where the valid `options` depend on the target OpenPGP.js function to be run.
See `./src/profiles.js` for examples of valid profile declarations.
