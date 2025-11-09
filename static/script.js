/* Collapsible card behavior */
document.querySelectorAll('.card-header').forEach(header => {
  header.addEventListener('click', () => {
    const card = header.parentElement;
    card.classList.toggle('open');

    // If opening, ensure body visible
    const targetId = header.getAttribute('data-target');
    const body = document.getElementById(targetId);
    // Also toggle using class on card
    if (card.classList.contains('open')) {
      body.style.maxHeight = body.scrollHeight + 'px';
    } else {
      body.style.maxHeight = null;
    }
  });
});

/* Toast system: auto close in 10s */
function showToast(message, timeout = 10000) {
  const container = document.getElementById('toast-container');
  const t = document.createElement('div');
  t.className = 'toast';
  t.innerText = message;
  container.appendChild(t);
  // auto remove
  setTimeout(() => {
    t.classList.add('fade-out');
    setTimeout(() => t.remove(), 700);
  }, timeout);
}

/* Helper: POST JSON and return JSON */
async function postJSON(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return res.json();
}

/* Copy buttons */
document.querySelectorAll('.copy-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const id = btn.getAttribute('data-copy');
    const el = document.getElementById(id);
    el.select();
    document.execCommand('copy');
    showToast('Copied to clipboard!');
  });
});

/* AES actions */
document.querySelector('[data-action="aes-encrypt"]').addEventListener('click', async (e) => {
  e.stopPropagation();
  const text = document.getElementById('aes-input').value;
  const pwd = document.getElementById('aes-password').value;
  if (!text || !pwd) { showToast('Text and password required'); return; }
  const res = await postJSON('/aes/encrypt', { text, password: pwd });
  if (res.ok) {
    document.getElementById('aes-result').value = res.result;
    showToast('AES encryption successful');
  } else showToast('Error: ' + (res.error || 'unknown'));
});

document.querySelector('[data-action="aes-decrypt"]').addEventListener('click', async (e) => {
  e.stopPropagation();
  const payload = document.getElementById('aes-result').value;
  const pwd = document.getElementById('aes-password').value;
  if (!payload || !pwd) { showToast('Payload and password required'); return; }
  const res = await postJSON('/aes/decrypt', { payload, password: pwd });
  if (res.ok) {
    document.getElementById('aes-result').value = res.result;
    showToast('AES decryption successful');
  } else showToast('Error: ' + (res.error || 'unknown'));
});

document.querySelector('[data-action="aes-clear"]').addEventListener('click', (e) => {
  e.stopPropagation();
  document.getElementById('aes-input').value = '';
  document.getElementById('aes-password').value = '';
  document.getElementById('aes-result').value = '';
  showToast('AES cleared');
});

/* RSA actions */
document.getElementById('rsa-generate').addEventListener('click', async (e) => {
  e.stopPropagation();
  const res = await fetch('/rsa/generate');
  const json = await res.json();
  if (json.ok) {
    document.getElementById('rsa-public-key').value = json.public_key;
    document.getElementById('rsa-private-key').value = json.private_key;
    showToast('RSA key pair generated');
  } else showToast('RSA generation failed');
});

document.querySelector('[data-action="rsa-encrypt"]').addEventListener('click', async (e) => {
  e.stopPropagation();
  const text = document.getElementById('rsa-input').value;
  const pub = document.getElementById('rsa-public-key').value;
  if (!text || !pub) { showToast('Text and public key required'); return; }
  const res = await postJSON('/rsa/encrypt', { text, public_key: pub });
  if (res.ok) {
    document.getElementById('rsa-result').value = res.result;
    showToast('RSA encrypted');
  } else showToast('Error: ' + (res.error || 'unknown'));
});

document.querySelector('[data-action="rsa-decrypt"]').addEventListener('click', async (e) => {
  e.stopPropagation();
  const payload = document.getElementById('rsa-result').value;
  const priv = document.getElementById('rsa-private-key').value;
  if (!payload || !priv) { showToast('Payload and private key required'); return; }
  const res = await postJSON('/rsa/decrypt', { payload, private_key: priv });
  if (res.ok) {
    document.getElementById('rsa-result').value = res.result;
    showToast('RSA decrypted');
  } else showToast('Error: ' + (res.error || 'unknown'));
});

document.querySelector('[data-action="rsa-clear"]').addEventListener('click', (e) => {
  e.stopPropagation();
  document.getElementById('rsa-public-key').value = '';
  document.getElementById('rsa-private-key').value = '';
  document.getElementById('rsa-input').value = '';
  document.getElementById('rsa-result').value = '';
  showToast('RSA cleared');
});

/* Caesar */
document.querySelector('[data-action="caesar-encrypt"]').addEventListener('click', async (e) => {
  e.stopPropagation();
  const text = document.getElementById('caesar-input').value;
  const shift = document.getElementById('caesar-shift').value;
  const res = await postJSON('/caesar/encrypt', { text, shift });
  if (res.ok) {
    document.getElementById('caesar-result').value = res.result;
    showToast('Caesar encrypted');
  } else showToast('Error: ' + (res.error || 'unknown'));
});

document.querySelector('[data-action="caesar-decrypt"]').addEventListener('click', async (e) => {
  e.stopPropagation();
  const text = document.getElementById('caesar-input').value;
  const shift = document.getElementById('caesar-shift').value;
  const res = await postJSON('/caesar/decrypt', { text, shift });
  if (res.ok) {
    document.getElementById('caesar-result').value = res.result;
    showToast('Caesar decrypted');
  } else showToast('Error: ' + (res.error || 'unknown'));
});

document.querySelector('[data-action="caesar-clear"]').addEventListener('click', (e) => {
  e.stopPropagation();
  document.getElementById('caesar-input').value = '';
  document.getElementById('caesar-result').value = '';
  showToast('Caesar cleared');
});

/* Base64 */
document.querySelector('[data-action="base64-encode"]').addEventListener('click', async (e) => {
  e.stopPropagation();
  const text = document.getElementById('base64-input').value;
  const res = await postJSON('/base64/encode', { text });
  if (res.ok) {
    document.getElementById('base64-result').value = res.result;
    showToast('Base64 encoded');
  } else showToast('Error: ' + (res.error || 'unknown'));
});

document.querySelector('[data-action="base64-decode"]').addEventListener('click', async (e) => {
  e.stopPropagation();
  const payload = document.getElementById('base64-input').value;
  const res = await postJSON('/base64/decode', { payload });
  if (res.ok) {
    document.getElementById('base64-result').value = res.result;
    showToast('Base64 decoded');
  } else showToast('Error: ' + (res.error || 'unknown'));
});

document.querySelector('[data-action="base64-clear"]').addEventListener('click', (e) => {
  e.stopPropagation();
  document.getElementById('base64-input').value = '';
  document.getElementById('base64-result').value = '';
  showToast('Base64 cleared');
});

/* Hash */
document.querySelector('[data-action="hash-generate"]').addEventListener('click', async (e) => {
  e.stopPropagation();
  const text = document.getElementById('hash-input').value;
  const algo = document.getElementById('hash-algorithm').value;
  const res = await postJSON('/hash/generate', { text, algorithm: algo });
  if (res.ok) {
    document.getElementById('hash-result').value = res.result;
    showToast('Hash generated');
  } else showToast('Error: ' + (res.error || 'unknown'));
});

document.querySelector('[data-action="hash-clear"]').addEventListener('click', (e) => {
  e.stopPropagation();
  document.getElementById('hash-input').value = '';
  document.getElementById('hash-result').value = '';
  showToast('Hash cleared');
});
