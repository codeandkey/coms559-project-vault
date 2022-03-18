// Configuration
const HTTP_PORT  = 8080;
const HTTPS_PORT = 8443;
const BUCKET = 'coms559-project-vault';

// Requires
const AWS     = require('aws-sdk');
const bodyParser = require('body-parser');
const express = require('express');
const fs      = require('fs');
const http    = require('http');
const https   = require('https');
const pug     = require('pug');

// S3 service
const S3 = new AWS.S3({apiVersion: '2006-03-01', region: 'us-east-1'});

// test: list buckets
S3.listBuckets((err, data) => {
    if (err)
        console.log('Error: ', err);
    else
        console.log('Success: ', data.Buckets);
})

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

// Body parsing
app.use(express.raw({limit: '256mb', type: '*/*'}));

// Web application routes
app.use('/static', express.static('static'));

app.get('/', (req, res) => {
    res.render('index');
});

// REST API routes

// User file upload
app.put('/api/upload/:user/:path(*)', (req, res) => {
    var params = {
        Bucket: BUCKET,
        Key: 'users/' + req.params.user + '/files/' + req.params.path,
        Body: req.body
    };

    S3.upload(params, (err, data) => {
        if (err)
        {
            console.log('Upload error: ', err);
            res.sendStatus(500);
        } else
        {
            console.log('Upload OK: ', data);
            res.send('Thanks');
        }
    });
});

// User file download.
app.get('/api/download/:user/:path(*)', (req, res) => {
    var params = {
        Bucket: BUCKET,
        Key: 'users/' + req.params.user + '/files/' + req.params.path,
    };

    S3.getObject(params, (err, data) => {
        if (err)
        {
            console.log('Download error: ', err);
            res.sendStatus(500);
        } else
        {
            console.log('Download OK: ', data);
            res.send(data.Body);
        }
    });
});

// User directory tree.
app.get('/api/tree/:user', (req, res) => {
    var params = {
        Bucket: BUCKET,
        Prefix: 'users/' + req.params.user + '/files',
    };

    S3.listObjectsV2(params, (err, data) => {
        if (err)
        {
            console.log('List error: ', err);
            res.sendStatus(500);
        } else
        {
            console.log('List OK: ', data);
            res.send(data);
        }
    });
});

// Launch servers
httpServer.listen(HTTP_PORT, () => {
    console.log(`Listening for HTTP requests on port ${HTTP_PORT}`);
});

httpsServer.listen(HTTPS_PORT, () => {
    console.log(`Listening for HTTPS requests on port ${HTTPS_PORT}`);
});
