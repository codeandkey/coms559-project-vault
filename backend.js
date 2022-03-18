// Configuration
const HTTP_PORT  = 8080
const HTTPS_PORT = 8443
const BUCKET = 'coms559-project-vault'
const SESSION_SECRET = '014a87d765b0299099cae11ba56a991a6dc259a0699e38c765f3816ca9a548ef'

// Requires
const AWS     = require('aws-sdk')
const bodyParser = require('body-parser')
const express = require('express')
const fs      = require('fs')
const http    = require('http')
const https   = require('https')
const pug     = require('pug')
const session = require('express-session')

// S3 service
const S3 = new AWS.S3({apiVersion: '2006-03-01', region: 'us-east-1'})

// SSL credentials
const privateKey = fs.readFileSync('cert/server.key', 'utf8')
const certificate = fs.readFileSync('cert/server.crt', 'utf8')
const credentials = {key: privateKey, cert: certificate}

// Globals
const app         = express()
const httpServer  = http.createServer(app)
const httpsServer = https.createServer(credentials, app)

// Template engine
app.set('view engine', 'pug')

// Body parsing
app.use(express.raw({limit: '256mb', type: 'application/octet-stream'}))
app.use(express.json({limit: '16kb', type: 'application/json'}))

// Web application routes
app.use('/static', express.static('static'))

app.get('/', (req, res) => {
    res.render('index')
})

// Session management
app.use(session({
    secret: SESSION_SECRET,
    cookie: { maxAge: 60000 },
    resave: false,
    saveUninitialized: false
}))

// REST API routes

// User file upload
app.put('/api/upload/:user/:path(*)', (req, res) => {
    var params = {
        Bucket: BUCKET,
        Key: 'users/' + req.params.user + '/files/' + req.params.path,
        Body: req.body
    }

    S3.upload(params, (err, data) => {
        if (err)
        {
            console.log('Upload error: ', err)
            res.sendStatus(500)
        } else
        {
            console.log('Upload OK: ', data)
            res.send('Thanks')
        }
    })
})

// User account creation
app.post('/api/register', (req, res) => {
    // Check if user exists
    var params = {
        Bucket: BUCKET,
        Prefix: 'users/' + req.params.user,
    }

    S3.listObjectsV2(params, (err, data) => {
        if (err)
        {
            console.log('Existing check error: ', err)
            res.sendStatus(500)
        } else
        {
            if (data.KeyCount > 0)
                res.send({status: 'error', message: 'User already exists!'})
        }
    })

    console.log(req.body)

    // Check input fields exist
    if (!req.body.username || !req.body.privkey || !req.body.pubkey || !req.body.kdf)
        return res.send({status: 'error', message: 'Invalid request'});

    // Check input field validity
    if (req.body.username.length > 32)
        return res.send({status: 'error', message: 'Invalid username (maximum 32 characters)'});

    if (req.body.username.includes('/'))
        return res.send({status: 'error', message: 'Invalid username (illegal characters)'});

    // Upload user information to s3
    var params = {
        Bucket: BUCKET,
        Key: 'users/' + req.params.user + '/info',
        Body: JSON.stringify({
            username: req.body.username,
            privkey: req.body.privkey,
            pubkey: req.body.pubkey,
            kdf: req.body.kdf,
        })
    }

    S3.upload(params, (err, data) => {
        if (err)
        {
            console.log('Upload error: ', err)
            res.sendStatus(500)
        } else
        {
            console.log('Upload OK: ', data)
            res.send({status: 'ok', message: 'Created user'})
        }
    })
})

// User file download.
app.get('/api/download/:user/:path(*)', (req, res) => {
    var params = {
        Bucket: BUCKET,
        Key: 'users/' + req.params.user + '/files/' + req.params.path,
    }

    S3.getObject(params, (err, data) => {
        if (err)
        {
            console.log('Download error: ', err)
            res.sendStatus(500)
        } else
        {
            console.log('Download OK: ', data)
            res.send({status: 'ok', body: data.Body})
        }
    })
})

// User directory tree.
app.get('/api/tree/:user', (req, res) => {
    var params = {
        Bucket: BUCKET,
        Prefix: 'users/' + req.params.user + '/files',
    }

    S3.listObjectsV2(params, (err, data) => {
        if (err)
        {
            console.log('List error: ', err)
            res.sendStatus(500)
        } else
        {
            console.log('List OK: ', data)

            res.send({
                status: 'ok',
                files: data.Contents.map(x => {
                    return {
                        name: x.Key,
                        modified: x.LastModified,
                        size: x.Size
                    }
                })
            })
        }
    })
})

// Set request logger
app.use((req, res, next) => {
    console.log('Request ' + req.method + ' ' + req.path + ' from ' + req.socket.remoteAddress)
})

// Launch servers
httpServer.listen(HTTP_PORT, () => {
    console.log(`Listening for HTTP requests on port ${HTTP_PORT}`)
})

httpsServer.listen(HTTPS_PORT, () => {
    console.log(`Listening for HTTPS requests on port ${HTTPS_PORT}`)
})
