// Web application index source
"use strict"

// Cookie parse method
function getCookie(name)
{
    var match = document.cookie.match(new RegExp('(^| )' + name + '=([^]+)'))
    if (match) return match[2]
}

// Try register
async function doRegister()
{
    // Get username field
    var username = $('#input-username').val()

    // Get password field
    var password = $('#input-password').val()

    // Derive PBKDF2 input from password
    var enc = new TextEncoder()

    var kdfInput = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    )

    console.log('generated KDF input', kdfInput)

    // Generate random KDF salt
    var salt = crypto.getRandomValues(new Uint8Array(16))
    var iterations = 10000

    console.log('KDF salt: ', salt)
    
    // Perform PBKDF2 and generate key
    var derivedKey = await crypto.subtle.deriveKey(
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

    console.log('derived symmetric key', derivedKey)

    // Generate public/private keypair
    var keyPair =  await window.crypto.subtle.generateKey(
        rsaAlgorithm, true, ['encrypt', 'decrypt']
    )

    console.log('generated keypair', keyPair)

    // Encode private key into buffer
    var privateKeyData = await window.crypto.subtle.exportKey('pkcs8', keyPair.privateKey)

    console.log('exported private key')

    // Encode public key into buffer
    var publicKeyData = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey)

    // Generate iv for encrypted private key
    var iv = crypto.getRandomValues(new Uint8Array(16))

    // Encrypt private key data with derived key
    var privateKeyEncoded = await window.crypto.subtle.encrypt(
        {
            name: 'AES-CBC',
            iv: iv,
        },
        derivedKey,
        privateKeyData,
    )

    console.log('privkey encoded ', privateKeyEncoded)

    // Send registration request to backend
    $.post({
        url: '/api/register',
        dataType: 'json',
        data: {
            username: username,
            privkey: {
                iv: iv,
                encoded: encodeBuffer(privateKeyEncoded),
            },
            pubkey: publicKeyData,
            kdf: {
                salt: salt,
                iterations: iterations,
            }
        }
    }, function(response) {
        console.log(response)
        if (response.status == 'ok') {
            showNotification('Created new account, you will be redirected shortly.')
            setTimeout(function() { doLogin(); }, 1000)
        } else {
            showNotification(response.message, 'error')
        }
    })
}

async function doLogin()
{
    
}