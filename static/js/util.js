/// Common javascript for each view.
/// Initializes crypto contexts and defines utility functions.

// Rename cryptography library if in WebKit
if (window.crypto && !window.crypto.subtle && window.crypto.webkitSubtle)
    window.crypto.subtle = window.crypto.webkitSubtle

// Check cryptography library is available
if (!window.crypto || !window.crypto.subtle)
    alert('Web cryptography API not available, this service is not available.')

console.log('WebCrypto ready.')

// RSA algorithm
var rsaAlgorithm = {
    name: 'RSA-OAEP',
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
}

// AES algorithm
var aesAlgorithm = {
    name: 'AES-CBC',
    length: 256,
}

// (PBKDF2 is defined inline as salt is required)

// Buffer hex encoding method
function encodeBuffer(buf)
{
    return [...new Uint8Array(buf)]
        .map(x => x.toString(16).padStart(2, '0'))
        .join('')
}

// Buffer hex decoding method
function decodeBuffer(hex)
{
    return new Uint8Array(hex.match(/../g).map(h=>parseInt(h, 16))).buffer
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
    $('#notify').css({opacity: 1.0})

    setTimeout(function() {
        $('#notify').css({opacity: 0.0})
    }, 4000)
}

function randomBytes(n)
{
    return crypto.getRandomValues(new Uint8Array(n))
}

/// Key derivation method
async function deriveKey(password, salt, iterations)
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