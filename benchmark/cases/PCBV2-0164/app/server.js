// Thin, standard Parse Server host. Nothing app-specific / no canary logic here.
// The canary (${PCB_FLAG}) is seeded from OUTSIDE via the Parse REST API by
// start.sh, so no business code is modified.
const express = require('express');

async function main() {
  const parseMod = require('parse-server');
  const ParseServer = parseMod.ParseServer || parseMod.default || parseMod;

  const config = {
    databaseURI: process.env.DATABASE_URI,
    appId: process.env.APP_ID || 'pcbApp',
    masterKey: process.env.MASTER_KEY || 'pcbMaster',
    serverURL: process.env.SERVER_URL || 'http://localhost:1337/parse',
    allowClientClassCreation: true,
    // Host-side start.sh seeds via masterKey; default 6.x masterKeyIps is loopback-only.
    masterKeyIps: ['0.0.0.0/0'],
  };

  const app = express();
  const server = new ParseServer(config);

  if (typeof server.start === 'function') {
    await server.start();
  }
  const parseApp = server.app || server;
  app.use('/parse', parseApp);
  app.get('/', (req, res) => res.status(200).send('ok'));
  app.get('/up', (req, res) => res.status(200).send('up'));

  const port = parseInt(process.env.PORT || '1337', 10);
  app.listen(port, '0.0.0.0', () => {
    console.log('parse-server ' + (process.env.PARSE_VER || '?') + ' listening on ' + port);
  });
}

main().catch(err => {
  console.error('FATAL', err);
  process.exit(1);
});
