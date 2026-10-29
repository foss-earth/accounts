# FOSS Earth accounts

Sign-in for the Earth app, the campus tour, and flight, and the pass-through
proxy that adds the Google Map Tiles key. The key stays on this process.
Browsers send an access token, never the key.

The decision record is
[Accounts and hosted basemaps](https://github.com/foss-earth/docs/blob/main/docs/proposals/accounts-and-hosted-basemaps.md).

## Run locally

Node.js 22 or newer. From this directory:

```sh
npm install
npm run dev
```

That listens on `https://localhost:8787` with a certificate in `build/dev-cert/`.
The apps on `localhost` already send sign-in there. The browser warns once
about the certificate. Provider secrets and the Maps key are environment
variables, listed in the spec. Without them the sign-in page has nothing to
offer and the tile proxy answers 503.

```sh
npm test
npm run accounts -- account disable --email person@example.com
```

The CLI opens `ACCOUNT_DATABASE` (default `build/accounts.sqlite` when the
server is started with `npm run dev`).

## Production

One machine, one egress IP. Restrict the Maps key to that IP and to the Map
Tiles API. Set `ACCOUNT_ORIGIN` to the public origin, `TLS_KEY` and `TLS_CERT`
to the certificate, and the provider and mail variables from the spec. `npm start`
listens on `PORT` (8787).
