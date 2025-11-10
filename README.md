# 🛡️ Encryption & Decryption Suite (Python Flask Web App)

🔗 **Live Demo:** [https://encryption-decryption-suite.onrender.com](https://encryption-decryption-suite.onrender.com)

A modern **Python-based Flask web application** that lets you encrypt and decrypt text using multiple algorithms — **AES, RSA, Caesar Cipher, Base64, and Hash generators.**
Built with a responsive layout, **toast notifications**, and a fully functional **Python backend**.

---

## 🌟 Features
- 🔒 **AES Encryption/Decryption** (256-bit AES-GCM)
- 🔑 **RSA Encryption/Decryption** with on-demand key generation
- 🔢 **Caesar Cipher** for basic shift encryption
- 🧬 **Base64 Encoding/Decoding**
- 🧮 **Hash Generator** (MD5, SHA-1, SHA-256, SHA-512)
- 💬 **Interactive Toast Notifications**

---

## 🧰 Tech Stack
| Layer | Technology |
|-------|-------------|
| Programming Language | **Python 3.x** |
| Backend Framework | **Flask** |
| Frontend | HTML, CSS , JavaScript |
| Cryptography | Python’s `cryptography` and `hashlib` libraries |
| Deployment | Render |

---

## ⚙️ Setup & Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/yourusername/encryption-decryption-suite.git
cd encryption-decryption-suite
```

### 2️⃣ Create a virtual environment
```bash
python -m venv venv
```

### 3️⃣ Activate the environment
**Windows:**
```bash
venv\Scripts\activate
```
**Mac/Linux:**
```bash
source venv/bin/activate
```

### 4️⃣ Install dependencies
```bash
pip install -r requirements.txt
```

### 5️⃣ Run the app
```bash
python app.py
```
Your app is now ready to deploy online using a hosting platform of your choice.

---

## 🌐 Deploy Online
### On [Render](https://render.com)
1. Push your project to GitHub.  
2. Create a new **Web Service** on Render.  
3. Configure:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
4. Click **Deploy** 🚀  

Your Flask web app will be live with a public URL like:  
`https://your-app-name.onrender.com`

---

## 🖼️ UI Preview
> 🔴 Elegant red-white gradient interface with collapsible cards and real-time notifications.  
> Each algorithm has its own panel for smooth, organized access.

---

## 🧑‍💻 Author
**Soniya Wakode**  
📧 [soniya.231104@gmail.com]  
🔗 [https://github.com/soniya231104]

---

## 📜 License
This project is licensed under the **MIT License** — free to use, modify, and distribute with proper attribution.