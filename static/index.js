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

// Keypair export method
async function exportKeyPair()
{
    console.log('Saving keypair to cookie.');

    var publicKeyJwk = await window.crypto.subtle.exportKey('jwk', gPublicKey);
    var privateKeyJwk = await window.crypto.subtle.exportKey('jwk', gPrivateKey);

    document.cookie = 'keyPair=' + JSON.stringify({publicKey: publicKeyJwk, privateKey: privateKeyJwk}) + ';SameSite=Strict';
    console.log("Saved keypair to cookie.");
}

// Keypair import method
async function importKeyPair(cookieKeyPair)
{
    console.log('Importing key pair.');

    gPublicKey = await window.crypto.subtle.importKey(
        'jwk',
        cookieKeyPair.publicKey,
        rsaAlgorithm,
        true,
        ['encrypt']
    );

    console.log('Imported public key.');

    gPrivateKey = await window.crypto.subtle.importKey(
        'jwk',
        cookieKeyPair.privateKey,
        rsaAlgorithm,
        true,
        ['decrypt']
    );

    console.log('Imported private key.');
}

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

// Try and import key from cookie
var cookieKeyPairString = getCookie('keyPair');
var keyReady;

if (cookieKeyPairString)
{
    keyReady = importKeyPair(JSON.parse(cookieKeyPairString));
} else
{
    keyReady = generateKeyPair();
}

keyReady.then(function() {
    // Set file upload listener
    document.getElementById('input').addEventListener('change', async function() {
        const fileList = this.files;

        // TODO: possibly stream or chunk file so it doesn't have to be loaded into memory
        var buffer = await fileList[0].arrayBuffer();

        console.log('uploaded ' + buffer.byteLength + ' bytes');

        var ct = await window.crypto.subtle.encrypt(
            rsaAlgorithm,
            gPublicKey,
            buffer
        );

        console.log('encrypted ' + ct.byteLength + ' bytes');

        var pt = await window.crypto.subtle.decrypt(
            rsaAlgorithm,
            gPrivateKey,
            ct
        );

        document.getElementById('viewer').innerHTML = encodeBuffer(buffer) + ' #### ' + encodeBuffer(ct) + ' #### ' + encodeBuffer(pt);
    }, false);
});