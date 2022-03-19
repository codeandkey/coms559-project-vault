// Authentication routines.

/// Responds with the second phase of the auth handshake.
async function doAuthResponse(username, password, nonce, privkey, kdf)
{
    /// First, perform key derivation
    var derivedKey = deriveKey(password, decodeBuffer(kdf.salt), kdf.iterations)

    /// Decrypt private key
    var privateKeyPKCS8 = await crypto.subtle.decrypt(
        {
            name: 'AES-CBC',
            length: 256,
            iv: privkey.iv
        },
        derivedKey,
        decodeBuffer(privkey.encoded)
    )

    /// Decode private key
    var privateKey = await crypto.subtle.importKey(
        'pkcs8',
        privateKeyPKCS8,
        rsaAlgorithm,
        true,
        ['encrypt', 'sign']
    )

    /// Sign nonce
    var nonceSignature = await crypto.subtle.sign(
        signAlgorithm,
        privateKey,
        decodeBuffer(nonce)
    )

    /// Send auth response to server
    var response = await $.post({
        url: '/api/auth',
        data: {
            username: username,
            nonceSignature: encodeBuffer(nonceSignature)
        }
    })

    if (response.status == 'ok')
    {
        // Store token in cookies
        document.cookie = ''
    }
}

/// Tries to authenticate with given credentials.
/// Returns a Promise(err, token) which is called with the result of
/// the authentication request.
async function doLogin(username, password)
{
    /// Send preauth request to server.
    $.post({
        url: '/api/preauth',
        data: { username: username }
    }, function (response) {
        if (response.status == 'ok')
            return doAuthResponse(response.nonce, response.privkey, response.kdf, password)

        showNotification(response.message, 'error')
    })
}