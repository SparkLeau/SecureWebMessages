const socket = io();
const chatMessages = document.getElementById("chat-messages");
const messageInput = document.getElementById("message-input");
const sendButton = document.getElementById("send-button");
const currentUsernameSpan = document.getElementById("current-username");
const usernameInput = document.getElementById("username-input");
const updateUsernameButton = document.getElementById("update-username-button");

let currentUsername = "";
let aesKey = null;

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
    let encoded = base64ToArrayBuffer(aesKey);
    return await window.crypto.subtle.encrypt(
      {
        name: "RSA-OAEP",
      },
      publicKey,
      encoded,
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

async function sendMessage(GeneratePublicKey, aesKey) {
    const message = messageInput.value.trim();
    if (message) {
        const publicKey = await crypto.subtle.importKey(
            "spki",
            base64ToArrayBuffer(GeneratePublicKey),
            {
                name: "RSA-OAEP",
                hash: "SHA-256"
            },
            true,
            ["encrypt"]
        );

        const encryptedMessage = await aesEncrypt(message);
        const encryptedKey = await encryptKeyWithRSA(publicKey, aesKey);

        socket.emit("send_message", {
            username: currentUsername,
            message: encryptedMessage.message,
            iv: encryptedMessage.iv,
            key: arrayBufferToBase64(encryptedKey)
        });

        messageInput.value = "";
    }
}

function updateUsername() {
    const newUsername = usernameInput.value.trim();
    if (newUsername && newUsername !== currentUsername) {
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

socket.on("set_username", (data) => {
    currentUsername = data.username;
    currentUsernameSpan.textContent = `Your username: ${currentUsername}`;
});

socket.on("username_updated", (data) => {
    addMessage(`${data.old_username} changed their name to ${data.new_username}`, "system");

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
});

socket.on("new_message", async (data) => {
    console.log(data);
    const decryptedMessage = await aesDecrypt(data.message, data.key, data.iv);
    addMessage(decryptedMessage, "user", data.username, data.avatar);
});

sendButton.addEventListener("click", sendMessage);
messageInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") sendMessage(publicKey, aesKey);
});
updateUsernameButton.addEventListener("click", updateUsername);


