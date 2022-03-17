// Configuration
const HTTP_PORT  = 8080;
const HTTPS_PORT = 8443;

// Requires
const express = require('express');
const fs      = require('fs');
const http    = require('http');
const https   = require('https');
const pug     = require('pug');

// SSL credentials
const privateKey = fs.readFileSync('cert/server.key', 'utf8');
const certificate = fs.readFileSync('cert/server.crt', 'utf8');
const credentials = {key: privateKey, cert: certificate};

// Globals
const app         = express();
const httpServer  = http.createServer(app);
const httpsServer = https.createServer(credentials, app);

// Template engine
app.set('view engine', 'pug');

// Static routes
app.use('/static', express.static('static'));

// Dynamic routes
app.get('/', (req, res) => {
    res.render('index');
});

// Launch servers
httpServer.listen(HTTP_PORT, () => {
    console.log(`Listening for HTTP requests on port ${HTTP_PORT}`);
});

httpsServer.listen(HTTPS_PORT, () => {
    console.log(`Listening for HTTP requests on port ${HTTPS_PORT}`);
});
