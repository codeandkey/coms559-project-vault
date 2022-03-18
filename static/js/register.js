// Registration view

// User needs to generate a keypair, derive AES key via KDF,
// encrypt the privkey and send everything over to POST.

// Wait for ajax response, and then direct the user to the main view on success.

// First, initialize WebCrypto API
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
    alert('Web Cryptography API not available, this service is not available.');
}

// Crypto algorithm
var rsaAlgorithm = {
    name: 'RSA-OAEP',
    modulusLength: 4096,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256'
};

// Global keypair variables
var gPublicKey;
var gPrivateKey;

// Keypair generation method
async function generateKeyPair() 
{
    console.log('Generating key pair.');

    return window.crypto.subtle.generateKey(
        rsaAlgorithm, true, ['encrypt', 'decrypt']
    ).then(function(newKeyPair) {
        gPublicKey = newKeyPair.publicKey;
        gPrivateKey = newKeyPair.privateKey;

        console.log("Generated key pair.");
        return exportKeyPair();
    });
}

// Show a temporary notification to the user.
function showNotification(message, type)
{

}

async function deriveKDF() {
}

// Generate keypair + derived key
function generateKeys()
{

}