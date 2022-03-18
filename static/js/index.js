// Web application index source
"use strict";

console.log('Starting crypto service');

// Rename cryptography library if in WebKit
if (window.crypto && !window.crypto.subtle && window.crypto.webkitSubtle)
{
    window.crypto.subtle = window.crypto.webkitSubtle;
}

// Check cryptography library is available
if (!window.crypto || !window.crypto.subtle)
{
    alert('Web cryptography API not available, this service is not available.');
}

// crypto algorithm
var rsaAlgorithm = {
    name: 'RSA-OAEP',
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
};

// Cookie parse method
function getCookie(name)
{
    var match = document.cookie.match(new RegExp('(^| )' + name + '=([^;]+)'));
    if (match) return match[2];
}

// Buffer hex encoding method
function encodeBuffer(buf)
{
    return [...new Uint8Array(buf)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('');
}

// Buffer hex decoding method
function decodeBuffer(hex)
{
    return new Uint8Array(hex.match(/../g).map(h=>parseInt(h, 16))).buffer;
}

// Show notification
function showNotification(message, kind)
{
    $('#notify').removeClass('alert-primary')
    $('#notify').removeClass('alert-danger')

    if (kind == 'ok')
        $('#notify').addClass('alert-primary')

    if (kind == 'error')
        $('#notify').addClass('alert-danger')

    $('#notify').text(message)
    $('#notify').css({opacity: 1.0});

    setTimeout(function() {
        $('#notify').css({opacity: 0.0});
    }, 4000);
}

// Try register
async function doRegister()
{
    // Get username field
    var username = $('#input-username').val();

    // Get password field
    var password = $('#input-password').val();

    // Derive PBKDF2 input from password
    var enc = new TextEncoder();

    var kdfInput = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    )

    // Generate random KDF salt
    var salt = crypto.getRandomValues(new Uint8Array(8));
    var iterations = 10000;
    
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
            size: 256,
        },
        true,
        ['encrypt', 'decrypt']
    )

    // Generate public/private keypair
    var keyPair =  await window.crypto.subtle.generateKey(
        rsaAlgorithm, true, ['encrypt', 'decrypt']
    );

    // Encode private key into buffer
    var privateKeyData = await window.crypto.subtle.exportKey('raw', keyPair.privateKey);

    // Encode public key into buffer
    var publicKeyData = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);

    // Generate iv for encrypted private key
    var iv = crypto.getRandomValues(new Uint8Array(16));

    // Encrypt private key data with derived key
    var privateKeyEncoded = await window.crypto.subtle.encrypt(
        {
            name: 'AES-CBC',
            iv: iv,
        },
        derivedKey,
        privateKeyData,
    )

    // Send registration request to backend
    $.ajax('/api/register', {
        username: username,
        privkey: {
            iv: iv,
            encoded: privateKeyEncoded,
        },
        pubkey: publicKeyData,
        kdf: {
            salt: salt,
            iterations: iterations,
        }
    }).done(function (response) {
        if (response.status == 'ok') {
            showNotification(response.message, 'ok')
        } else {
            showNotification(response.message, 'error')
        }
    });
}