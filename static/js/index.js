const socket = io();
const chatMessages = document.getElementById("chat-messages");
const messageInput = document.getElementById("message-input");
const sendButton = document.getElementById("send-button");
const currentUsernameSpan = document.getElementById("current-username");
const usernameInput = document.getElementById("username-input");
const updateUsernameButton = document.getElementById("update-username-button");

let currentUsername = "";
let aesKey = null;
let publicKey = null;
let rsaKeyPair = null;
let publicKeys = {}; // Stocker les clés publiques des autres utilisateurs

// RSA Key Generation
async function generateRSAKeyPair() {
    return await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
}

// Générer une clé AES unique pour l'utilisateur
async function generateKey() {
    aesKey = await window.crypto.subtle.generateKey(
        {
            name: "AES-CBC",
            length: 256,
        },
        true,
        ["encrypt", "decrypt"]
    );
    return aesKey;
}

// Génération d'un IV aléatoire
function generateIV() {
    return crypto.getRandomValues(new Uint8Array(16));
}

// Convertir une clé en Base64
async function keyToBase64(key) {
    const raw = await crypto.subtle.exportKey("raw", key);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

// Convertir Base64 en clé AES
async function base64ToKey(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return await crypto.subtle.importKey("raw", bytes, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
}

// Convertir un array buffer en Base64
function arrayBufferToBase64(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

// Convertir Base64 en array buffer
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// Chiffrement AES-CBC
async function encryptKeyWithRSA(publicKey, aesKey) {
    const rawKey = await crypto.subtle.exportKey("raw", aesKey);
    return await window.crypto.subtle.encrypt(
        {
            name: "RSA-OAEP",
        },
        publicKey,
        rawKey
    );
}

async function decryptKeyWithRSA(encryptedKeyBase64) {
    const encryptedKey = base64ToArrayBuffer(encryptedKeyBase64);
    const rawKey = await window.crypto.subtle.decrypt(
        {
            name: "RSA-OAEP",
        },
        rsaKeyPair.privateKey,
        encryptedKey
    );
    return await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-CBC" },
        true,
        ["encrypt", "decrypt"]
    );
}

async function aesEncrypt(message) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const iv = generateIV();
    const encryptedData = await crypto.subtle.encrypt(
        { name: "AES-CBC", iv: iv },
        aesKey,
        data
    );
    return {
        message: arrayBufferToBase64(encryptedData),
        iv: arrayBufferToBase64(iv)
    };
}

// Déchiffrement AES-CBC
async function aesDecrypt(encryptedMessage, aesKey, ivBase64) {
    const iv = base64ToArrayBuffer(ivBase64);
    const encryptedData = base64ToArrayBuffer(encryptedMessage);

    try {
        const decryptedData = await crypto.subtle.decrypt(
            { name: "AES-CBC", iv: iv },
            aesKey,
            encryptedData
        );
        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    } catch (err) {
        console.error("Erreur lors du déchiffrement : ", err);
        return null;
    }
}

function storeKeys() {
    // Stocker les clés publiques des autres utilisateurs
    const publicKeysBase64 = {};
    for (const [username, key] of Object.entries(publicKeys)) {
        const keyExported = crypto.subtle.exportKey("spki", key);
        keyExported.then((key) => {
            publicKeysBase64[username] = arrayBufferToBase64(key);
            sessionStorage.setItem("publicKeys", JSON.stringify(publicKeysBase64));
        }).catch((err) => {
            console.error("Error exporting public key:", err);
        });
    }
}

async function retrieveKeys() {
    // Récupérer la clé publique de l'utilisateur
    const aesKeyBase64 = sessionStorage.getItem("aesKey");
    if (aesKeyBase64) {
        aesKey = await crypto.subtle.importKey(
            "raw",
            base64ToArrayBuffer(aesKeyBase64),
            { name: "AES-CBC" },
            true,
            ["encrypt", "decrypt"]
        );
    } else {
        console.log("No AES key found in session storage");
    }
    // Récupérer les clés publiques des autres utilisateurs
    const publicKeysBase64 = JSON.parse(sessionStorage.getItem("publicKeys"));
    if (publicKeysBase64) {
        for (const [username, keyBase64] of Object.entries(publicKeysBase64)) {
            const key = await crypto.subtle.importKey(
                "spki",
                base64ToArrayBuffer(keyBase64),
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256"
                },
                true,
                ["encrypt"]
            );
            publicKeys[username] = key;
        }
    } else {
        console.log("No public keys found in session storage");
    }
}

function removePublicKey(username) {
    // Supprimer la clé publique du stockage de session
    const publicKeysBase64 = JSON.parse(sessionStorage.getItem("publicKeys"));
    if (publicKeysBase64 && publicKeysBase64[username]) {
        delete publicKeysBase64[username];
        sessionStorage.setItem("publicKeys", JSON.stringify(publicKeysBase64));
    }

    // Supprimer la clé publique de la mémoire
    if (publicKeys[username]) {
        delete publicKeys[username];
    }
}

async function sendMessage() {
    const message = messageInput.value.trim();
    if (message && Object.keys(publicKeys).length > 0) {
        const encryptedMessage = await aesEncrypt(message);
        let encryptedKeys = {};

        for (const [username, key] of Object.entries(publicKeys)) {
            const encryptedKey = await encryptKeyWithRSA(key, aesKey);
            encryptedKeys[username] = arrayBufferToBase64(encryptedKey);
        }

        socket.emit("send_message", {
            username: currentUsername,
            message: encryptedMessage.message,
            iv: encryptedMessage.iv,
            keys: encryptedKeys
        });

        messageInput.value = "";
    } else {
        console.error("Message or public keys are missing");
    }
}

function updateUsername() {
    const newUsername = usernameInput.value.trim();
    if (newUsername && newUsername !== currentUsername) {
        // Mettre à jour les clés publiques dans le stockage de session
        const publicKeysBase64 = JSON.parse(sessionStorage.getItem("publicKeys"));
        if (publicKeysBase64 && publicKeysBase64[currentUsername]) {
            publicKeysBase64[newUsername] = publicKeysBase64[currentUsername];
            delete publicKeysBase64[currentUsername];
            sessionStorage.setItem("publicKeys", JSON.stringify(publicKeysBase64));
        }

        socket.emit("update_username", { username: newUsername });
        usernameInput.value = "";
    }
}

function addMessage(message, type, username = "", avatar = "") {
    const messageElement = document.createElement("div");
    messageElement.className = "message";

    if (type === "user") {
        const avatarImg = document.createElement("img");
        avatarImg.src = avatar;
        avatarImg.alt = "Avatar";
        avatarImg.className = "avatar";
        messageElement.appendChild(avatarImg);

        const contentDiv = document.createElement("div");
        contentDiv.className = "message-content";

        const usernameDiv = document.createElement("div");
        usernameDiv.className = "message-username";
        usernameDiv.textContent = username;
        contentDiv.appendChild(usernameDiv);

        const messageText = document.createElement("div");
        messageText.className = "message-text";
        messageText.textContent = message;
        contentDiv.appendChild(messageText);

        messageElement.appendChild(contentDiv);
    } else {
        messageElement.className = "system-message";
        messageElement.textContent = message;
    }

    const chatMessages = document.getElementById("chat-messages");
    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// Initialisation de la clé AES
generateKey().then(async (aesKey) => {
    return await keyToBase64(aesKey);
});

// Génération de la paire de clés RSA et envoi de la clé publique au serveur
generateRSAKeyPair().then(async (keyPair) => {
    rsaKeyPair = keyPair;
    const publicKeyExported = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyBase64 = arrayBufferToBase64(publicKeyExported);
    socket.emit("public_key", { publicKey: publicKeyBase64 });
});

socket.on("set_username", (data) => {
    currentUsername = data.username;
    currentUsernameSpan.textContent = `Your username: ${currentUsername}`;
});

socket.on("username_updated", (data) => {
    addMessage(`${data.old_username} changed their name to ${data.new_username}`, "system");

    // Mettre à jour les clés publiques dans le stockage de session
    const publicKeysBase64 = JSON.parse(sessionStorage.getItem("publicKeys"));
    if (publicKeysBase64 && publicKeysBase64[data.old_username]) {
        publicKeysBase64[data.new_username] = publicKeysBase64[data.old_username];
        delete publicKeysBase64[data.old_username];
        sessionStorage.setItem("publicKeys", JSON.stringify(publicKeysBase64));
    }

    // Mettre à jour les clés publiques en mémoire
    if (publicKeys[data.old_username]) {
        publicKeys[data.new_username] = publicKeys[data.old_username];
        delete publicKeys[data.old_username];
    }

    if (data.old_username === currentUsername) {
        currentUsername = data.new_username;
        currentUsernameSpan.textContent = `Your username: ${currentUsername}`;
    }
});

socket.on("user_joined", (data) => {
    addMessage(`${data.username} joined the chat`, "system");
});

socket.on("user_left", (data) => {
    addMessage(`${data.username} left the chat`, "system");
    removePublicKey(data.username);
});

socket.on("new_message", async (data) => {
    const decryptedKey = await decryptKeyWithRSA(data.key);
    const rawDecryptedKey = await crypto.subtle.exportKey("raw", decryptedKey);

    const decryptedMessage = await aesDecrypt(data.message, decryptedKey, data.iv);
    addMessage(decryptedMessage, "user", data.username, data.avatar);
});

// Socket listener to receive the public key
socket.on("public_key", async (data) => {
    if (data.publicKey) {
        const importedPublicKey = await crypto.subtle.importKey(
            "spki",
            base64ToArrayBuffer(data.publicKey),
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["encrypt"]
        );
        publicKeys[data.username] = importedPublicKey; // Stocker la clé publique avec le nom d'utilisateur
        storeKeys();
    } else {
        console.error("Received public key is undefined");
    }
});

socket.on("connect", () => {
    // Delay to ensure keys are stored before requesting them
    setTimeout(() => {
        socket.emit("request_public_key");
    }, 1000);
});

// Retrieve keys from session storage on page load
window.addEventListener("load", retrieveKeys);

sendButton.addEventListener("click", sendMessage);
messageInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") sendMessage();
});
updateUsernameButton.addEventListener("click", updateUsername);


