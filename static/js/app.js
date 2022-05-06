/// Frontend source.
/// This file manages all the behavior available in the web app.

/// ==== Constants  ====

// Number of iterations in KDF
var KDF_ITERATIONS = 10000;

// RSA algorithm for keypairs
var ALGORITHM_RSA = {
    name: 'RSA-OAEP',
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
}

/// ==== Session state ====
var session = {
    privateKey: null,
    username: null,
    token: null,
}


/// ==== Buffer encoding ====

/**
 * Encodes an ArrayBuffer into a hexadecimal string format.
 * 
 * @param {ArrayBufferLike} buf Input buffer
 * @returns {String} Encoded string.
 */
function encodeHex(buf)
{
    return [...new Uint8Array(buf)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('')
}

/**
 * Decodes a hexadecimal string into an ArrayBuffer.
 * 
 * @param {String} hex Input string
 * @returns {ArrayBufferLike} Decoded buffer.
 */
function decodeHex(hex)
{
    return new Uint8Array(hex.match(/../g).map(h=>parseInt(h, 16))).buffer
}

/**
 * Generates a buffer of random bytes.
 * 
 * @param {Number} n Size of output buffer.
 * @returns {Uint8Array} Buffer of n random bytes.
 */
var randomBytes = n => crypto.getRandomValues(new Uint8Array(n))

/**
 * Converts a byte count to a human readable format.
 * 
 * @param {Number} x Bytes
 * @returns String
 */
function formatBytes(x)
{
    const units = ['B', 'KB', 'MB', 'GB']
    let l = 0, n = parseInt(x, 10) || 0

    while(n >= 1024 && ++l)
        n /= 1024

    return(n.toFixed(n < 10 && l > 0 ? 1 : 0) + ' ' + units[l])
}

/// ==== Notifications ====

/**
 * Displays a notification to the user.
 * 
 * @param {String} kind Notification type. Should be one of 'ok', 'error'.
 * @param {String} message Notification content.
 */
function showNotification(kind, message)
{
    $('#notify').removeClass('alert-primary')
    $('#notify').removeClass('alert-danger')

    if (kind == 'ok')
        $('#notify').addClass('alert-primary')

    if (kind == 'error')
        $('#notify').addClass('alert-danger')

    $('#notify').text(message)
    $('#notify').css({opacity: 1.0})

    setTimeout(function() {
        $('#notify').css({opacity: 0.0})
    }, 4000)
}

function switchToFileView()
{
    // Load authenticated view
    $('#login-view').css({ opacity: 0 })

    setTimeout(() => {
        $('#login-view').css({ display: 'none' })
        $('#app-view').css({ display: 'block' })
        $('#app-view').css({ opacity: 1 })
    }, 1000)
}

/// ==== Cryptography ====

/**
 * Performs key derivation given a password, salt, and iterations. If
 * iterations are not provided the default KDF_ITERATIONS is used instead.
 * 
 * @param {String} password KDF input password
 * @param {ArrayBufferLike} salt Base key (salt)
 * @param {Number} iterations Number of iterations.
 */
async function deriveKey(password, salt, iterations)
{
    if (iterations == null)
        iterations = KDF_ITERATIONS;

    // Derive PBKDF2 input from password
    var enc = new TextEncoder()

    var kdfInput = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    )

    // Perform PBKDF2 and generate key
    return await crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            hash: 'SHA-512',
            salt: salt,
            iterations: iterations,
        },
        kdfInput,
        {
            name: 'AES-CBC',
            length: 256,
        },
        true,
        ['encrypt', 'decrypt']
    )
}

/**
 * Generates materials for a new user identity. This consists of the process:
 * 
 * 1) New RSA keypair generated.
 * 2) New symmetric key derived through KDF with password + random salt.
 * 3) Private key encrypted with symmetric key + random IV.
 * 4) Encoded private key, IV, public key and KDF parameters stored in identity.
 * 
 * The returned object is of the format:
 * 
 * {
 *   privateKey: {
 *     encoded: '<HEX DATA>',
 *     iv:      '<HEX DATA>',
 *     kdf: {
 *       salt: '<HEX DATA>',
 *       iterations: N
 *     }
 *   },
 *   publicKey: <JWK-encoded CryptoKey>
 * }
 * 
 * @param {String} password User password string.
 * @return {Object} New user identity to be sent to server.
 */
async function generateIdentity(password)
{
    // Generate public/private keypair
    var keyPair =  await window.crypto.subtle.generateKey(
        ALGORITHM_RSA, true, ['encrypt', 'decrypt']
    )

    // Encode private key into buffer
    var privateKeyData = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey)

    // Encode public key into buffer
    var publicKeyData = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey)

    // Generate new derived key
    var salt = randomBytes(16)
    var derivedKey = await deriveKey(password, salt)

    // Generate iv for encrypted private key
    var iv = randomBytes(16)

    // Encrypt private key data with derived key
    var privateKeyEncoded = await window.crypto.subtle.encrypt(
        {
            name: 'AES-CBC',
            length: 256,
            iv: iv,
        },
        derivedKey,
        privateKeyData,
    )

    return {
        privateKey: {
            encoded: encodeHex(privateKeyEncoded),
            iv: encodeHex(iv),
            kdf: {
                salt: encodeHex(salt),
                iterations: KDF_ITERATIONS,
            }
        },
        publicKey: publicKeyData,
    }
}

/**
 * Performs the second stage of the authentication handshake. The consists of
 * the process:
 * 
 * 1) Receive nonce, encoded private key, IV, KDF parameters, server pubkey from server
 * 2) Re-derive symmetric key using KDF parameters
 * 3) Decrypt private key using symmetric key
 * 4) Decrypt nonce with private key
 * 5) Re-encrypt nonce with server's public key
 * 
 * @param {Object} preauth Server preauth response.
 * @return {Object} Auth request to be sent to server (excluding username field)
 */
async function generateAuthResponse(password, preauth)
{
    // Perform key derivation with password and preauth KDF parameters
    var derivedKey = await deriveKey(
        password,
        decodeHex(preauth.privateKey.kdf.salt),
        preauth.privateKey.kdf.iterations
    )

    console.log('derivedKey', derivedKey)

    // Decrypt private key data
    try {
        var privateKeyData = await crypto.subtle.decrypt(
            {
                name: 'AES-CBC',
                length: 256,
                iv: decodeHex(preauth.privateKey.iv)
            },
            derivedKey,
            decodeHex(preauth.privateKey.encoded)
        )
    } catch (err) {
        showNotification('error', 'Incorrect password.')
        return;
    }

    console.log('privateKeyData', privateKeyData)

    // Parse PKCS8 into CryptoKey
    var privateKey = await crypto.subtle.importKey(
        'pkcs8',
        privateKeyData,
        ALGORITHM_RSA,
        true,
        ['decrypt']
    )

    console.log('privateKey', privateKey)
    console.log('preauth nonce', preauth.nonce)

    session.privateKey = privateKey // TODO refactor this

    // Decrypt server nonce
    var nonceData = await crypto.subtle.decrypt(
        ALGORITHM_RSA,
        privateKey,
        decodeHex(preauth.nonce)
    )

    console.log('nonceData', nonceData)

    // Construct response
    return {
        nonce: encodeHex(nonceData),
    }
}

/// ==== Backend requests ====

/**
 * Sends a POST request to the backend and waits for a response. If an error
 * occurs, an error message is displayed to the user and 'null' is returned
 * from the promise. Otherwise, the response from the server is returned.
 * 
 * @param {String} endpoint Target backend endpoint.
 * @param {Object} data Request parameters.
 * @returns {Any} null if an error occurs, otherwise the received Object.
 */
async function makeRequest(endpoint, data, method)
{
    if (method == null)
        method = 'POST'

    response = await $.ajax({
        method: method,
        url: endpoint,
        data: data,
    })

    if (response.status == 'error')
    {
        console.log('request error:', response.message)
        return showNotification('error', response.message)
    }

    console.log('request ', endpoint, ', response ', response)

    return response
}

/// === App actions ====

/**
 * Tries to log the user in. Uses the DOM input fields 'input-username' and
 * 'input-password' to retrieve the user's name and pass respectively. On
 * successful login, opens the app view and sets the global session token.
 */
async function doLogin()
{
    // Get input fields
    var username = $('#input-username').val()
    var password = $('#input-password').val()

    // Send preauth request
    var preauth = await makeRequest('/api/preauth', { username: username })
    if (!preauth) return;

    console.log('preauth:',preauth)

    // Perform second stage
    var authReq = await generateAuthResponse(password, preauth)

    // Check for password fail
    if (!authReq)
        return;

    authReq.username = username

    console.log('authreq body: ', authReq)

    var authResp = await makeRequest('/api/auth', authReq)
    if (!authResp) return;

    console.log('authenticated OK:', authResp)

    session.token = authResp.token
    session.publicKey = preauth.publicKey
    session.username = username

    // Serialize cookie
    document.cookie = '';
    for (const [k, v] of Object.entries(session))
        document.cookie += k + '=' + v + ';'

    updateFiles();
    switchToFileView()
}

/**
 * Sends a registration request to the server. Uses the DOM input fields
 * 'input-username' and 'input-password' to retrieve the user's name and pass
 * respectively. On success, tries to perform an auth and enter the user into
 * the web app.
 */
async function doRegister()
{
    // Get input fields
    var username = $('#input-username').val()
    var password = $('#input-password').val()

    // Generate new identity, incorporate username
    var identity = await generateIdentity(password)
    identity.username = username

    // Wait for registration request
    if (await makeRequest('/api/register', identity))
        return doLogin()
}

/**
 * Upload click bind to prompt user for a file.
 */
function startUploadFile() {
    $('#upload-input').trigger('click')
}

/**
 * Share click bind to prompt user for a recipient.
 */
function shareFile(path) {
    var un = window.prompt('Who will you share the file with?')
    doShareFile(path, un)
}

/**
 * Queries the user's available files and lists them in the UI.
 */
async function updateFiles()
{
    var resp = await makeRequest('/api/tree/' + session.username, { token: session.token });

    if (!resp)
        return;

    const sregex = /^shared\/[^\/]+\//g;

    $('#files').html('<thead><tr><th scope="col">Owner</th><th scope="col">File</th><th scope="col">Size</th><th scope="col"></th><th scope="col"></th></tr></thead>')

    for (var i = 0; i < resp.files.length; ++i)
    {
        var fname = resp.files[i].name;
        var found;

        var owners = 'YOU';

        var arrow = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-arrow-right" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M1 8a.5.5 0 0 1 .5-.5h11.793l-3.147-3.146a.5.5 0 0 1 .708-.708l4 4a.5.5 0 0 1 0 .708l-4 4a.5.5 0 0 1-.708-.708L13.293 8.5H1.5A.5.5 0 0 1 1 8z"/></svg>';

        while (true)
        {
            found = fname.match(sregex);

            if (!found || found.length < 0)
                break;

            owners = found[0].split('/')[1] + arrow + owners;
            fname = fname.substr(found[0].length)
        }

        $('#files').append(
            '<tr><td>' + owners + '</td><td>'
            + fname + '</td><td>'
            + formatBytes(resp.files[i].size)
            + '</td><td><button class="btn mr-1" onclick="downloadFile(\'' + resp.files[i].name + '\')">Download</button>'
            + '<button class="btn ml-1" onclick="shareFile(\'' + resp.files[i].name + '\')">Share</button></td></tr>')
    }
}



/**
 * Downloads a user file.
 */
async function downloadFile(path)
{
    var resp = await makeRequest('/api/download/' + session.username + '/' + path, { token: session.token })

    if (!resp)
        return;

    var keyBuf = decodeHex(resp.data.keys)

    console.log('found keybuf', keyBuf)

    var keys = await crypto.subtle.decrypt(
        ALGORITHM_RSA,
        session.privateKey,
        keyBuf
    )

    console.log('decrypted keys', encodeHex(keys), keys)

    var key = keys.slice(0, 16)
    var iv = keys.slice(16)

    console.log('key', encodeHex(key))
    console.log('iv', encodeHex(iv))
    var symKey = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC', iv: iv }, false, ['decrypt'])

    var ctstr = decodeHex(resp.data.filedata)

    var decrypted = await window.crypto.subtle.decrypt(
        {
            name: 'AES-CBC',
            length: 256,
            iv: iv,
        },
        symKey,
        ctstr,
    )

    var blob = new Blob([new Uint8Array(decrypted)], {type: "application/octet-stream"});
    var link = document.createElement('a');
    link.href = window.URL.createObjectURL(blob);
    var parts = path.split('/')
    var fileName = parts[parts.length - 1]
    link.download = fileName;
    link.click();
}

/**
 * Uploads a file once the user has selected one.
 */
async function doUploadFile(input) {
    var reader = new FileReader();

    reader.onload = async function(e) {
        // Make symmetric key
        var iv = randomBytes(16)
        var key = randomBytes(16)

        var symKey = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC', iv: iv }, false, ['encrypt'])

        var encrypted = await window.crypto.subtle.encrypt(
            {
                name: 'AES-CBC',
                length: 256,
                iv: iv,
            },
            symKey,
            reader.result,
        )

        // Encrypt symmetric key with our public key
        console.log('jwk: ', JSON.stringify(session.publicKey))

        var publicKey = await crypto.subtle.importKey('jwk', session.publicKey, ALGORITHM_RSA, false, ['encrypt'])
        console.log('imported publickey')
        console.log(reader.result)

        console.log(publicKey)

        var keyData = new Uint8Array([...key, ...iv])

        var encryptedKey = await crypto.subtle.encrypt(
            ALGORITHM_RSA,
            publicKey,
            keyData,
        )

        console.log('encrypted', encrypted)
        console.log('encryptedKey', encryptedKey)

        // Send upload request
        var res = await makeRequest('/api/upload/' + session.username + '/' + input.files[0].name, {
            token: session.token,
            data: {
                keys: encodeHex(encryptedKey),
                filedata: encodeHex(encrypted)
            }
        }, 'PUT')

        if (!res)
            return;

        showNotification('ok', 'Uploaded file ' + input.files[0].name);
        updateFiles();
    }

    reader.readAsArrayBuffer(input.files[0]);
}

/**
 * Shares an existing file to another user.
 */
async function doShareFile(path, user) {
    // Query other user's public key
    var pkResp = await makeRequest('/api/key/' + user, {}, 'POST')

    if (!pkResp)
        return;

    var otherPublicKey = await crypto.subtle.importKey('jwk', pkResp.publicKey, ALGORITHM_RSA, false, ['encrypt'])
    console.log('imported otherpublickey')

    // Download and decrypt file data
    var resp = await makeRequest('/api/download/' + session.username + '/' + path, { token: session.token })

    if (!resp)
        return;

    var keyBuf = decodeHex(resp.data.keys)

    console.log('found keybuf', keyBuf)

    var keys = await crypto.subtle.decrypt(
        ALGORITHM_RSA,
        session.privateKey,
        keyBuf
    )

    console.log('decrypted keys', encodeHex(keys), keys)

    var key = keys.slice(0, 16)
    var iv = keys.slice(16)

    console.log('key', encodeHex(key))
    console.log('iv', encodeHex(iv))
    var symKey = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC', iv: iv }, false, ['decrypt'])

    var ctstr = decodeHex(resp.data.filedata)

    var decrypted = await window.crypto.subtle.decrypt(
        {
            name: 'AES-CBC',
            length: 256,
            iv: iv,
        },
        symKey,
        ctstr,
    )

    // Make symmetric key
    var iv = randomBytes(16)
    var key = randomBytes(16)

    var symKey = await crypto.subtle.importKey('raw', key, { name: 'AES-CBC', iv: iv }, false, ['encrypt'])

    var encrypted = await window.crypto.subtle.encrypt(
        {
            name: 'AES-CBC',
            length: 256,
            iv: iv,
        },
        symKey,
        decrypted,
    )

    // Encrypt symmetric key with their public key

    var keyData = new Uint8Array([...key, ...iv])

    var encryptedKey = await crypto.subtle.encrypt(
        ALGORITHM_RSA,
        otherPublicKey,
        keyData,
    )

    console.log('encrypted', encrypted)
    console.log('encryptedKey', encryptedKey)

    // Send upload request
    var res = await makeRequest('/api/share/' + user + '/' + session.username + '/' + path, {
        token: session.token,
        data: {
            keys: encodeHex(encryptedKey),
            filedata: encodeHex(encrypted)
        }
    }, 'PUT')

    if (!res)
        return;

    showNotification('ok', 'Shared file ' + path + ' with ' + user);
    updateFiles()
}

// ==== Restore state ====

var stored = document.cookie.split('; ').reduce((result, v) => {
  const k = v.split('=');
  result[k[0]] = k[1];
  return result;
}, {})

console.log('previous session: ', stored)

if ('username' in stored && 'privateKey' in stored && 'token' in stored)
{
    session = stored;
    switchToFileView();
}