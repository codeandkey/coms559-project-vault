// Configuration
const HTTP_PORT  = 8080
const HTTPS_PORT = 8443
const BUCKET = 'coms559-project-vault'
const SESSION_SECRET = '014a87d765b0299099cae11ba56a991a6dc259a0699e38c765f3816ca9a548ef'

// Requires
const AWS     = require('aws-sdk')
const bodyParser = require('body-parser')
const crypto  = require('crypto')
const express = require('express')
const fs      = require('fs')
const http    = require('http')
const https   = require('https')
const pug     = require('pug')
const session = require('express-session')

// S3 service
const S3 = new AWS.S3({apiVersion: '2006-03-01', region: 'us-east-1'})

// SSL credentials
const privateKeyData = fs.readFileSync('cert/server.key', 'utf8')
const certificate = fs.readFileSync('cert/server.crt', 'utf8')
const credentials = {key: privateKeyData, cert: certificate}

const privateKey = crypto.createPrivateKey(privateKeyData)

const publicKeyEncoded = crypto.createPublicKey(certificate).export({
    type: 'pkcs1',
    format: 'jwk'
})

// Globals
const app         = express()
const httpServer  = http.createServer(app)
const httpsServer = https.createServer(credentials, app)

// Template engine
app.set('view engine', 'pug')

// Body parsing
app.use(express.raw({limit: '256mb', type: 'application/octet-stream'}))
app.use(express.json({limit: '256mb', type: 'application/json'}))
app.use(express.urlencoded({limit: '256mb', extended: true}))

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

/**
 * Verifies a user token is valid and not expired.
 * 
 * @param {String} username 
 * @param {String} token 
 * @param {Function(error)} cb 
 */
function verifyToken(username, token, cb) {
    var params = {
        Bucket: BUCKET,
        Key: 'users/' + username + '/token',
    }

    S3.getObject(params, (err, data) => {
        if (err) {
            return cb(err);
        }

        var body = JSON.parse(data.Body);
        var expires = Date.parse(body.expires);

        if (token != body.token)
            return cb('incorrect');

        if (Date.now() >= expires)
            return cb('expired');

        cb();
    })
}

// REST API routes

// User file upload
app.put('/api/upload/:user/:path(*)', (req, res) => {
    verifyToken(req.params.user, req.body.token, (err) => {
        if (err) {
            return res.send({status: 'error', message: 'Invalid token: ' + err})
        }

        var params = {
            Bucket: BUCKET,
            Key: 'users/' + req.params.user + '/files/' + req.params.path,
            Body: JSON.stringify(req.body.data)
        }

        S3.upload(params, (err, data) => {
            if (err)
            {
                console.log('Upload error: ', err)
                res.sendStatus(500)
            } else
            {
                console.log('Upload OK: ', data)
                res.send({status: 'ok'})
            }
        })
    })
})

// User file share 
app.put('/api/share/:dest/:user/:path(*)', (req, res) => {
    verifyToken(req.params.user, req.body.token, (err) => {
        if (err) {
            return res.send({status: 'error', message: 'Invalid token: ' + err})
        }
        // Check if user exists
        var params = {
            Bucket: BUCKET,
            Prefix: 'users/' + req.params.dest,
        }

        S3.listObjectsV2(params, (err, data) => {
            if (err)
            {
                console.log('Existing check error: ', err)
                return res.send({status: 'error', message: 'No such user'})
            }

            var params = {
                Bucket: BUCKET,
                Key: 'users/' + req.params.dest + '/files/shared/' + req.params.user + '/' + req.params.path,
                Body: JSON.stringify(req.body.data)
            }

            S3.upload(params, (err, data) => {
                if (err)
                {
                    console.log('Upload error: ', err)
                    res.sendStatus(500)
                } else
                {
                    console.log('Upload OK: ', data)
                    res.send({status: 'ok'})
                }
            })
        })
    })
})

// User account creation
app.post('/api/register', (req, res) => {
    // Check if user exists
    var params = {
        Bucket: BUCKET,
        Prefix: 'users/' + req.body.username,
    }

    S3.listObjectsV2(params, (err, data) => {
        if (err)
        {
            console.log('Existing check error: ', err)
            return res.sendStatus(500)
        }

        if (data.KeyCount > 0)
            return res.send({status: 'error', message: 'Username is taken, please choose another one.'})

        console.log(req.body)

        // Check input fields exist
        if (!req.body.username || !req.body.privateKey || !req.body.publicKey)
            return res.send({status: 'error', message: 'Invalid request (missing fields)'});

        // Check input field validity
        if (req.body.username.length > 32)
            return res.send({status: 'error', message: 'Invalid username (maximum 32 characters)'});

        if (req.body.username.includes('/'))
            return res.send({status: 'error', message: 'Invalid username (illegal characters)'});

        // Upload user information to s3
        var params = {
            Bucket: BUCKET,
            Key: 'users/' + req.body.username + '/info',
            Body: JSON.stringify({
                username: req.body.username,
                privateKey: req.body.privateKey,
                publicKey: req.body.publicKey,
            })
        }

        S3.upload(params, (err, data) => {
            if (err)
            {
                console.log('Upload error: ', err)
                return res.sendStatus(500)
            }

            console.log('Created new user ' + req.body.username)
            return res.send({status: 'ok', message: 'Created user'})
        })
    })
})

// User preauthentication
app.post('/api/preauth', (req, res) => {
    console.log('Preauthenticating', req.body.username)

    // Check if user exists
    var params = {
        Bucket: BUCKET,
        Prefix: 'users/' + req.body.username,
    }

    S3.listObjectsV2(params, (err, data) => {
        if (err)
        {
            console.log('Existing check error: ', err)
            return res.sendStatus(500)
        }

        if (data.KeyCount == 0)
        {
            console.log(req.body.username + ' login failed: no such user')
            return res.send({status: 'error', message: 'Login failed, please try again.'})
        }

        params = {
            Bucket: BUCKET,
            Key: 'users/' + req.body.username + '/info',
        }

        // Get user information
        S3.getObject(params, (err, userdata) => {
            if (err)
            {
                console.log('Get user check err: ' + err)
                return res.sendStatus(500)
            }

            var nonce = crypto.randomBytes(32)
            var expires = new Date()

            var userdataBody = JSON.parse(userdata.Body)

            //console.log('received userdata ' + JSON.stringify(userdataBody));

            expires.setMinutes(expires.getMinutes() + 5)

            // Set user auth salt and expiration
            var params = {
                Bucket: BUCKET,
                Key: 'users/' + req.body.username + '/nonce',
                Body: JSON.stringify({ nonce: nonce.toString('hex'), expires: expires.toUTCString() })
            }

            console.log('user public key data: ',userdataBody.publicKey)

            var userPublicKey = crypto.createPublicKey({
                key: userdataBody.publicKey,
                format: 'jwk',
            })

            console.log('user public key: ', userPublicKey)

            // Encrypt nonce for response
            var encryptedNonce = crypto.publicEncrypt(
                {
                    key: userPublicKey,
                    oaepHash: 'sha256'
                },
                nonce
            )
            console.log('encryptedNonce: ', encryptedNonce)

            S3.upload(params, (err, data) => {
                if (err)
                {
                    console.log(err)
                    return res.sendStatus(500)
                }

                console.log('Starting auth for ' + req.body.username + ': userdata', userdata)

                res.send({
                    status: 'ok',
                    nonce: encryptedNonce.toString('hex'),
                    expires: expires.toUTCString(),
                    privateKey: userdataBody.privateKey,
                    publicKey: userdataBody.publicKey, 
                })
            })
        })
    })
})

// User authentication
app.post('/api/auth', (req, res) => {
    console.log('Authenticating', req.body.username)

    // Query user nonce
    var params = {
        Bucket: BUCKET,
        Key: 'users/' + req.body.username + '/nonce',
    }

    S3.getObject(params, (err, data) => {
        if (err)
        {
            console.log(err)
            return res.send({status: 'error', message: 'Login failed, please try again.'})
        }

        // Parse encoded nonce
        var clientNonce = Buffer.from(req.body.nonce, 'hex')

        // Check the nonce values match
        if (clientNonce.toString('hex') != JSON.parse(data.Body).nonce)
        {
            console.log(req.body.username + ' auth failed, bad nonce')
            return res.send({status: 'error', message: 'Login failed, please try again.'})
        }

        // Set user auth token
        var token = crypto.randomBytes(32)
        var expires = new Date();

        // 1 hour session
        expires.setMinutes(expires.getMinutes() + 60);

        // Set user auth token
        var params = {
            Bucket: BUCKET,
            Key: 'users/' + req.body.username + '/token',
            Body: JSON.stringify({token: token.toString('hex'), expires: expires.toUTCString()})
        }

        S3.upload(params, (err, data) => {
            if (err)
            {
                console.log(err)
                return res.sendStatus(500)
            }

            console.log('Authenticated ' + req.body.username)

            res.send({
                status: 'ok',
                token: token.toString('hex'),
                expires: expires.toUTCString(),
            })
        })
    })
})

// User file download.
app.post('/api/download/:user/:path(*)', (req, res) => {
    verifyToken(req.params.user, req.body.token, (err) => {
        if (err)
            return res.send({status: 'error', 'message': 'Invalid token: ' + err})

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
                res.send({status: 'ok', data: JSON.parse(data.Body)})
            }
        })
    })
})

// User directory tree.
app.post('/api/tree/:user', (req, res) => {
    verifyToken(req.params.user, req.body.token, (err) => {
        if (err)
            return res.send({status: 'error', 'message': 'Invalid token: ' + err})

        var params = {
            Bucket: BUCKET,
            Prefix: 'users/' + req.params.user + '/files',
        }

        S3.listObjectsV2(params, (err, data) => {
            if (err)
                return res.sendStatus(500)

            console.log('List OK: ', data)

            let filter = x => {
                if (x.startsWith(params.Prefix + '/'))
                    return x.substring(params.Prefix.length + 1)

                return x
            }

            res.send({
                status: 'ok',
                files: data.Contents.map(x => {
                    return {
                        name: filter(x.Key),
                        modified: x.LastModified,
                        size: x.Size
                    }
                })
            })
        })
    })
})

// User key request
app.post('/api/key/:user', (req, res) => {
    // Check if user exists
    var params = {
        Bucket: BUCKET,
        Prefix: 'users/' + req.params.user,
    }

    S3.listObjectsV2(params, (err, data) => {
        if (err)
        {
            console.log('Existing check error: ', err)
            return res.sendStatus(500)
        }

        if (data.KeyCount == 0)
        {
            console.log(req.params.user + ' keyreq failed: no such user')
            return res.send({status: 'error', message: 'No such user'})
        }

        params = {
            Bucket: BUCKET,
            Key: 'users/' + req.params.user + '/info',
        }

        // Get user information
        S3.getObject(params, (err, userdata) => {
            if (err)
            {
                console.log('Get user check err: ' + err)
                return res.sendStatus(500)
            }

            var nonce = crypto.randomBytes(32)
            var expires = new Date()

            var userdataBody = JSON.parse(userdata.Body)

            res.send({
                status: 'ok',
                publicKey: userdataBody.publicKey, 
            })
        })
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
