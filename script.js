// Security Config 2026
const ITERATIONS = 600000; 
const SALT_SIZE = 16;      
const IV_SIZE = 12;        

const status = document.getElementById('status');

// Helper to update UI status
const log = (msg) => status.innerText = msg;

// Generate a key from password using PBKDF2
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey(
        "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
    );
    return window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
        baseKey,
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
    );
}

// Encrypt File
document.getElementById('btn-encrypt').onclick = async () => {
    const file = document.getElementById('file-input').files[0];
    const password = document.getElementById('password').value;
    if (!file || !password) return log("Error: Select a file and enter a password.");

    log("Encrypting...");
    const salt = window.crypto.getRandomValues(new Uint8Array(SALT_SIZE));
    const iv = window.crypto.getRandomValues(new Uint8Array(IV_SIZE));
    const key = await deriveKey(password, salt);
    
    const content = await file.arrayBuffer();
    const encryptedContent = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv }, key, content
    );

    // Bundle: [SALT] + [IV] + [ENCRYPTED DATA]
    const blob = new Blob([salt, iv, new Uint8Array(encryptedContent)], { type: "application/octet-stream" });
    download(blob, file.name + ".enc");
    log("Encryption Complete.");
};

// Decrypt File
document.getElementById('btn-decrypt').onclick = async () => {
    const file = document.getElementById('file-input').files[0];
    const password = document.getElementById('password').value;
    if (!file || !password) return log("Error: Select an .enc file and enter the password.");

    log("Decrypting...");
    const data = new Uint8Array(await file.arrayBuffer());
    const salt = data.slice(0, SALT_SIZE);
    const iv = data.slice(SALT_SIZE, SALT_SIZE + IV_SIZE);
    const encryptedData = data.slice(SALT_SIZE + IV_SIZE);

    try {
        const key = await deriveKey(password, salt);
        const decryptedContent = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv }, key, encryptedData
        );
        
        const blob = new Blob([decryptedContent], { type: "application/octet-stream" });
        download(blob, file.name.replace(".enc", ""));
        log("Decryption Successful.");
    } catch (e) {
        log("Error: Decryption failed (Wrong password or corrupted file).");
    }
};

function download(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}
