// Utility functions
function showTab(tabName) {
    // Hide all tab contents
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => content.classList.remove('active'));
    
    // Remove active class from all tab buttons
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => button.classList.remove('active'));
    
    // Show selected tab content
    document.getElementById(tabName).classList.add('active');
    
    // Add active class to selected tab button
    event.target.classList.add('active');
}

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    element.select();
    document.execCommand('copy');
    
    // Show feedback
    const button = event.target;
    const originalText = button.textContent;
    button.textContent = 'Copied!';
    setTimeout(() => {
        button.textContent = originalText;
    }, 2000);
}

// AES Encryption/Decryption
async function aesEncrypt() {
    const input = document.getElementById('aes-input').value;
    const password = document.getElementById('aes-password').value;
    
    if (!input || !password) {
        alert('Please enter both text and password');
        return;
    }
    
    try {
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );
        
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt']
        );
        
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encrypted = await crypto.subtle.encrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encoder.encode(input)
        );
        
        const encryptedArray = new Uint8Array(encrypted);
        const result = new Uint8Array(salt.length + iv.length + encryptedArray.length);
        result.set(salt, 0);
        result.set(iv, salt.length);
        result.set(encryptedArray, salt.length + iv.length);
        
        document.getElementById('aes-result').value = btoa(String.fromCharCode(...result));
    } catch (error) {
        alert('Encryption failed: ' + error.message);
    }
}

async function aesDecrypt() {
    const input = document.getElementById('aes-input').value;
    const password = document.getElementById('aes-password').value;
    
    if (!input || !password) {
        alert('Please enter both encrypted text and password');
        return;
    }
    
    try {
        const encryptedData = new Uint8Array(atob(input).split('').map(c => c.charCodeAt(0)));
        const salt = encryptedData.slice(0, 16);
        const iv = encryptedData.slice(16, 28);
        const encrypted = encryptedData.slice(28);
        
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode(password),
            { name: 'PBKDF2' },
            false,
            ['deriveBits', 'deriveKey']
        );
        
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );
        
        const decrypted = await crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            encrypted
        );
        
        const decoder = new TextDecoder();
        document.getElementById('aes-result').value = decoder.decode(decrypted);
    } catch (error) {
        alert('Decryption failed: ' + error.message);
    }
}

function clearAES() {
    document.getElementById('aes-input').value = '';
    document.getElementById('aes-password').value = '';
    document.getElementById('aes-result').value = '';
}

// RSA Encryption/Decryption
let rsaKeyPair = null;

async function generateRSAKeys() {
    try {
        rsaKeyPair = await crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            ['encrypt', 'decrypt']
        );
        
        const publicKey = await crypto.subtle.exportKey('spki', rsaKeyPair.publicKey);
        const privateKey = await crypto.subtle.exportKey('pkcs8', rsaKeyPair.privateKey);
        
        document.getElementById('rsa-public-key').value = btoa(String.fromCharCode(...new Uint8Array(publicKey)));
        document.getElementById('rsa-private-key').value = btoa(String.fromCharCode(...new Uint8Array(privateKey)));
    } catch (error) {
        alert('Key generation failed: ' + error.message);
    }
}

async function rsaEncrypt() {
    const input = document.getElementById('rsa-input').value;
    const publicKeyText = document.getElementById('rsa-public-key').value;
    
    if (!input) {
        alert('Please enter text to encrypt');
        return;
    }
    
    if (!publicKeyText) {
        alert('Please generate or enter a public key');
        return;
    }
    
    try {
        const publicKey = await crypto.subtle.importKey(
            'spki',
            new Uint8Array(atob(publicKeyText).split('').map(c => c.charCodeAt(0))),
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['encrypt']
        );
        
        const encoder = new TextEncoder();
        const encrypted = await crypto.subtle.encrypt(
            { name: 'RSA-OAEP' },
            publicKey,
            encoder.encode(input)
        );
        
        document.getElementById('rsa-result').value = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    } catch (error) {
        alert('RSA encryption failed: ' + error.message);
    }
}

async function rsaDecrypt() {
    const input = document.getElementById('rsa-input').value;
    const privateKeyText = document.getElementById('rsa-private-key').value;
    
    if (!input) {
        alert('Please enter text to decrypt');
        return;
    }
    
    if (!privateKeyText) {
        alert('Please generate or enter a private key');
        return;
    }
    
    try {
        const privateKey = await crypto.subtle.importKey(
            'pkcs8',
            new Uint8Array(atob(privateKeyText).split('').map(c => c.charCodeAt(0))),
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['decrypt']
        );
        
        const encryptedData = new Uint8Array(atob(input).split('').map(c => c.charCodeAt(0)));
        const decrypted = await crypto.subtle.decrypt(
            { name: 'RSA-OAEP' },
            privateKey,
            encryptedData
        );
        
        const decoder = new TextDecoder();
        document.getElementById('rsa-result').value = decoder.decode(decrypted);
    } catch (error) {
        alert('RSA decryption failed: ' + error.message);
    }
}

function clearRSA() {
    document.getElementById('rsa-input').value = '';
    document.getElementById('rsa-result').value = '';
}

// Caesar Cipher
function caesarEncrypt() {
    const input = document.getElementById('caesar-input').value;
    const shift = parseInt(document.getElementById('caesar-shift').value);
    
    if (!input) {
        alert('Please enter text to encrypt');
        return;
    }
    
    let result = '';
    for (let i = 0; i < input.length; i++) {
        let char = input[i];
        if (char.match(/[a-z]/i)) {
            const code = input.charCodeAt(i);
            if (code >= 65 && code <= 90) {
                char = String.fromCharCode(((code - 65 + shift) % 26) + 65);
            } else if (code >= 97 && code <= 122) {
                char = String.fromCharCode(((code - 97 + shift) % 26) + 97);
            }
        }
        result += char;
    }
    
    document.getElementById('caesar-result').value = result;
}

function caesarDecrypt() {
    const input = document.getElementById('caesar-input').value;
    const shift = parseInt(document.getElementById('caesar-shift').value);
    
    if (!input) {
        alert('Please enter text to decrypt');
        return;
    }
    
    let result = '';
    for (let i = 0; i < input.length; i++) {
        let char = input[i];
        if (char.match(/[a-z]/i)) {
            const code = input.charCodeAt(i);
            if (code >= 65 && code <= 90) {
                char = String.fromCharCode(((code - 65 - shift + 26) % 26) + 65);
            } else if (code >= 97 && code <= 122) {
                char = String.fromCharCode(((code - 97 - shift + 26) % 26) + 97);
            }
        }
        result += char;
    }
    
    document.getElementById('caesar-result').value = result;
}

function clearCaesar() {
    document.getElementById('caesar-input').value = '';
    document.getElementById('caesar-result').value = '';
}

// Base64 Encoding/Decoding
function base64Encode() {
    const input = document.getElementById('base64-input').value;
    
    if (!input) {
        alert('Please enter text to encode');
        return;
    }
    
    try {
        const encoded = btoa(input);
        document.getElementById('base64-result').value = encoded;
    } catch (error) {
        alert('Encoding failed: ' + error.message);
    }
}

function base64Decode() {
    const input = document.getElementById('base64-input').value;
    
    if (!input) {
        alert('Please enter text to decode');
        return;
    }
    
    try {
        const decoded = atob(input);
        document.getElementById('base64-result').value = decoded;
    } catch (error) {
        alert('Decoding failed: Invalid base64 string');
    }
}

function clearBase64() {
    document.getElementById('base64-input').value = '';
    document.getElementById('base64-result').value = '';
}

// Hash Generator
async function generateHash() {
    const input = document.getElementById('hash-input').value;
    const algorithm = document.getElementById('hash-algorithm').value;
    
    if (!input) {
        alert('Please enter text to hash');
        return;
    }
    
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(input);
        
        let hashAlgorithm;
        switch (algorithm) {
            case 'SHA-256':
                hashAlgorithm = 'SHA-256';
                break;
            case 'SHA-512':
                hashAlgorithm = 'SHA-512';
                break;
            case 'MD5':
                // Note: MD5 is not available in Web Crypto API
                // Using a simple implementation for demonstration
                document.getElementById('hash-result').value = 'MD5 not available in browser. Use SHA-256 instead.';
                return;
            case 'SHA-1':
                hashAlgorithm = 'SHA-1';
                break;
            default:
                hashAlgorithm = 'SHA-256';
        }
        
        const hashBuffer = await crypto.subtle.digest(hashAlgorithm, data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        document.getElementById('hash-result').value = hashHex;
    } catch (error) {
        alert('Hash generation failed: ' + error.message);
    }
}

function clearHash() {
    document.getElementById('hash-input').value = '';
    document.getElementById('hash-result').value = '';
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    // Add any initialization code here
});
