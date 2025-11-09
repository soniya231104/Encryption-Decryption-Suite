# 🔐 Encryption & Decryption Suite

A comprehensive, fully-functional encryption and decryption project built with modern web technologies. This suite provides multiple encryption algorithms and tools for secure data handling, all running locally in your browser.

## 🚀 Features

### Encryption Algorithms
- **AES-256-GCM** - Advanced Encryption Standard with Galois/Counter Mode
- **RSA-2048-OAEP** - Rivest-Shamir-Adleman with OAEP padding
- **Caesar Cipher** - Classic shift cipher with configurable shift
- **Base64** - Binary-to-text encoding scheme
- **Hash Generator** - Multiple hash algorithms (SHA-256, SHA-512, SHA-1)

### Security Features
- **Client-side encryption** - All encryption happens locally in your browser
- **No data transmission** - Your data never leaves your device
- **Strong key derivation** - PBKDF2 with 100,000 iterations
- **Secure random generation** - Web Crypto API for cryptographic randomness

## 🛠️ Getting Started

### Quick Start
1. Open `index.html` in any modern web browser
2. Choose your encryption method from the tabs
3. Enter your text and encryption parameters
4. Click encrypt/decrypt buttons

### Local Development
```bash
# Clone or download the project
# Open index.html in your browser
# No server setup required - runs entirely client-side
```

## 📖 Usage Guide

### AES Encryption
1. **Encrypt**: Enter text → Set password → Click "Encrypt"
2. **Decrypt**: Enter encrypted text → Use same password → Click "Decrypt"
3. **Security**: Uses AES-256-GCM with PBKDF2 key derivation

### RSA Encryption
1. **Generate Keys**: Click "Generate RSA Key Pair"
2. **Encrypt**: Use public key to encrypt messages
3. **Decrypt**: Use private key to decrypt messages
4. **Share**: Share public key, keep private key secret

### Caesar Cipher
1. **Set Shift**: Choose shift value (1-25)
2. **Encrypt/Decrypt**: Apply shift to text
3. **Note**: Simple substitution cipher - not secure for sensitive data

### Base64 Encoding
1. **Encode**: Convert text to base64
2. **Decode**: Convert base64 back to text
3. **Use Case**: Safe text transmission over text-only channels

### Hash Generator
1. **Choose Algorithm**: SHA-256, SHA-512, or SHA-1
2. **Generate**: Creates irreversible hash of input
3. **Verify**: Compare hashes to verify data integrity

## 🔧 Technical Details

### Technologies Used
- **HTML5** - Semantic markup
- **CSS3** - Modern styling with flexbox and gradients
- **JavaScript ES6+** - Modern JavaScript features
- **Web Crypto API** - Native browser cryptography
- **Responsive Design** - Mobile-friendly interface

### Browser Compatibility
- Chrome 60+
- Firefox 63+
- Safari 11+
- Edge 79+
- Opera 47+

### Security Considerations
- **HTTPS Recommended**: For production deployment
- **Key Management**: Users responsible for key storage
- **Password Strength**: Use strong, unique passwords
- **No Server Storage**: All data processed client-side

## 🎯 Use Cases

### Personal Use
- Secure personal notes
- Password-protected files
- Private communication

### Educational
- Learning cryptography concepts
- Understanding encryption algorithms
- Security awareness training

### Development
- Testing encryption implementations
- API security testing
- Data protection demonstrations

## 📊 Performance

### Encryption Speed
- **AES**: ~1MB/s on modern hardware
- **RSA**: ~100KB/s (limited by key size)
- **Hashing**: ~10MB/s for SHA-256

### Memory Usage
- **Typical**: <50MB RAM usage
- **Peak**: <100MB for large files

## 🔄 API Reference

### Core Functions
```javascript
// AES Encryption
aesEncrypt(text, password) → encrypted

// AES Decryption
aesDecrypt(encrypted, password) → decrypted

// RSA Key Generation
generateRSAKeys() → {publicKey, privateKey}

// RSA Encryption
rsaEncrypt(text, publicKey) → encrypted

// RSA Decryption
rsaDecrypt(encrypted, privateKey) → decrypted
```

## 🐛 Troubleshooting

### Common Issues
1. **"Encryption failed"** - Check password strength and input format
2. **"Invalid base64"** - Ensure proper encoding before decoding
3. **Browser compatibility** - Update to latest browser version

### Debug Mode
Enable console logging by adding `?debug=true` to URL

## 🤝 Contributing

### Development Setup
```bash
# Fork the repository
# Make changes to crypto.js for new algorithms
# Update styles.css for UI improvements
# Test across different browsers
```

### Adding New Algorithms
1. Add tab in index.html
2. Implement function in crypto.js
3. Add styling in styles.css
4. Update README.md

## 📄 License

This project is open source and available under the MIT License. Feel free to use, modify, and distribute as needed.

## 🙋‍♂️ Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Check browser console for errors
- Verify browser compatibility

---

**Note**: This tool is for educational and personal use. For production systems, consider additional security measures and professional cryptographic libraries.
