const ITERATIONS = 600000; 
const SALT_SIZE = 16;      
const IV_SIZE = 12;        

const log = (msg) => document.getElementById('status').innerText = msg;

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

document.getElementById('btn-encrypt').onclick = async () => {
    const files = document.getElementById('file-input').files;
    const password = document.getElementById('password').value;
    if (files.length === 0 || !password) return log("Error: Select files and enter a password.");

    log("Encrypting and Zipping...");
    const zip = new JSZip();
    const salt = window.crypto.getRandomValues(new Uint8Array(SALT_SIZE));

    for (const file of files) {
        const iv = window.crypto.getRandomValues(new Uint8Array(IV_SIZE));
        const key = await deriveKey(password, salt);
        const content = await file.arrayBuffer();
        
        const encryptedContent = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv }, key, content
        );

        // Combine IV and Ciphertext for each file
        const combined = new Uint8Array(iv.length + encryptedContent.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encryptedContent), iv.length);
        
        zip.file(file.name + ".enc", combined);
    }

    // Add the salt to the zip so we can derive the key later
    zip.file("metadata.salt", salt);

    const zipBlob = await zip.generateAsync({ type: "blob" });
    const url = URL.createObjectURL(zipBlob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "EncryptedVault.zip";
    a.click();
    log("Vault Created Successfully.");
};
