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

// NOUVELLE VARIABLE: Paire de clés RSA spécifique pour la signature
let rsaSignKeyPair = null;
// NOUVELLE VARIABLE: Stockage des clés de vérification des autres utilisateurs
let verifyKeys = {};

// RSA Key Generation
async function generateRSAKeyPair() {
    return await window.crypto.subtle.generateKey(
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

// NOUVELLE FONCTION: Génération de clés RSA pour la signature
async function generateRSASignKeyPair() {
    return await window.crypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256"
        },
        true,
        ["sign", "verify"]
    );
}

// NOUVELLE FONCTION: Signer un message avec la clé privée RSA
async function signMessage(message) {
    try {
        console.log("Début de la signature du message:", message.substring(0, 20) + "...");
        
        // Si rsaSignKeyPair n'est pas disponible, convertir la clé principale
        if (!rsaSignKeyPair) {
            rsaSignKeyPair = await convertToSignKeyPair(rsaKeyPair);
        }
        
        // Hacher le message avant signature
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        
        // Signer le message haché
        const signature = await window.crypto.subtle.sign(
            {
                name: "RSASSA-PKCS1-v1_5"
            },
            rsaSignKeyPair.privateKey,
            data
        );
        
        const signatureBase64 = arrayBufferToBase64(signature);
        console.log("Signature générée avec succès:", signatureBase64.substring(0, 20) + "...");
        return signatureBase64;
    } catch (error) {
        console.error("Erreur lors de la signature du message:", error);
        return null;
    }
}

// NOUVELLE FONCTION: Vérifier une signature avec la clé publique RSA
async function verifySignature(message, signatureBase64, username) {
    try {
        console.log(`Début de la vérification de signature pour ${username}:`, message.substring(0, 20) + "...");
        console.log("Signature à vérifier:", signatureBase64.substring(0, 20) + "...");
        
        // Vérifier si nous avons la clé publique de cet utilisateur
        if (!publicKeys[username]) {
            console.error("Pas de clé publique disponible pour cet utilisateur:", username);
            return false;
        }
        
        // Extraire la clé publique et la convertir en clé de vérification
        const publicKeyData = await window.crypto.subtle.exportKey("spki", publicKeys[username]);
        const verifyKey = await window.crypto.subtle.importKey(
            "spki",
            publicKeyData,
            {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256"
            },
            false,
            ["verify"]
        );
        
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const signature = base64ToArrayBuffer(signatureBase64);
        
        // Vérifier la signature
        const result = await window.crypto.subtle.verify(
            {
                name: "RSASSA-PKCS1-v1_5"
            },
            verifyKey,
            signature,
            data
        );
        
        console.log("Résultat de la vérification:", result ? "Signature valide ✓" : "Signature invalide ⚠️");
        return result;
    } catch (error) {
        console.error("Erreur lors de la vérification de signature:", error);
        return false;
    }
}

// NOUVELLE FONCTION: Exporter la clé publique de vérification
async function exportVerifyKey(key) {
    const exported = await window.crypto.subtle.exportKey("spki", key);
    return arrayBufferToBase64(exported);
}

// NOUVELLE FONCTION: Importer une clé publique de vérification
async function importVerifyKey(keyBase64) {
    try {
        return await window.crypto.subtle.importKey(
            "spki",
            base64ToArrayBuffer(keyBase64),
            {
                name: "RSASSA-PKCS1-v1_5",
                hash: "SHA-256"
            },
            false,
            ["verify"]
        );
    } catch (error) {
        console.error("Erreur lors de l'importation de la clé de vérification:", error);
        return null;
    }
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
    return window.crypto.getRandomValues(new Uint8Array(16));
}

// Convertir une clé en Base64
async function keyToBase64(key) {
    const raw = await window.crypto.subtle.exportKey("raw", key);
    return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

// Convertir Base64 en clé AES
async function base64ToKey(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return await window.crypto.subtle.importKey("raw", bytes, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
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
    const rawKey = await window.crypto.subtle.exportKey("raw", aesKey);
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
    return await window.crypto.subtle.importKey(
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
    const encryptedData = await window.crypto.subtle.encrypt(
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
        const decryptedData = await window.crypto.subtle.decrypt(
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
        const keyExported = window.crypto.subtle.exportKey("spki", key);
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
        aesKey = await window.crypto.subtle.importKey(
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
            const key = await window.crypto.subtle.importKey(
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

// MODIFIER la fonction sendMessage pour inclure la signature et les logs
async function sendMessage() {
    const message = messageInput.value.trim();
    if (message && Object.keys(publicKeys).length > 0) {
        console.log("Envoi d'un message:", message);
        
        // Chiffrer le message comme avant
        const encryptedMessage = await aesEncrypt(message);
        let encryptedKeys = {};

        for (const [username, key] of Object.entries(publicKeys)) {
            const encryptedKey = await encryptKeyWithRSA(key, aesKey);
            encryptedKeys[username] = arrayBufferToBase64(encryptedKey);
        }

        // NOUVEAU: Signer le message original
        const signature = await signMessage(message);
        console.log("Message signé, signature:", signature ? "Générée" : "Non générée");

        // Envoyer le message chiffré avec la signature
        socket.emit("send_message", {
            username: currentUsername,
            message: encryptedMessage.message,
            iv: encryptedMessage.iv,
            keys: encryptedKeys,
            signature: signature // NOUVEAU: Inclure la signature
        });

        messageInput.value = "";
    } else {
        console.error("Message ou clés publiques manquantes");
    }
}

function updateUsername() {
    const newUsername = usernameInput.value.trim();
    if (Object.keys(publicKeys).includes(newUsername)) {
        alert("Username already taken. Please choose a different username.");
        return;
    }
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

// MODIFIER la fonction addMessage pour inclure le statut de la signature
function addMessage(message, type, username = "", avatar = "", signatureStatus = "") {
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

        // Ajouter l'indicateur de signature
        if (signatureStatus) {
            const signatureIndicator = document.createElement("span");
            signatureIndicator.className = "signature-status";
            signatureIndicator.title = signatureStatus.verified ? 
                "Message authentifié" : 
                "Signature non vérifiée";
            signatureIndicator.textContent = signatureStatus.verified ? " ✓" : " ⚠️";
            messageText.appendChild(signatureIndicator);
        }

        contentDiv.appendChild(messageText);
        messageElement.appendChild(contentDiv);
    } else {
        messageElement.className = "system-message";
        messageElement.textContent = message;
    }

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
    const publicKeyExported = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    const publicKeyBase64 = arrayBufferToBase64(publicKeyExported);
    socket.emit("public_key", { publicKey: publicKeyBase64 });
});

socket.on("set_username", (data) => {
    currentUsername = data.username;
    currentUsernameSpan.textContent = `Your username: ${currentUsername}`;
    
    // Partager la clé de vérification si disponible
    if (rsaSignKeyPair) {
        shareVerifyKey();
    }
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

// MODIFIER la fonction socket.on("new_message") pour vérifier la signature avec logs
socket.on("new_message", async (data) => {
    try {
        console.log("Réception d'un message de:", data.username);
        
        const decryptedKey = await decryptKeyWithRSA(data.key);
        const decryptedMessage = await aesDecrypt(data.message, decryptedKey, data.iv);
        
        console.log("Message déchiffré:", decryptedMessage);
        
        let signatureStatus = null;
        
        if (data.signature) {
            console.log("Signature trouvée, vérification...");
            const isVerified = await verifySignature(
                decryptedMessage,
                data.signature,
                data.username
            );
            signatureStatus = {
                verified: isVerified
            };
            console.log("Statut de la signature:", isVerified ? "Vérifié ✓" : "Non vérifié ⚠️");
        } else {
            console.log("Pas de signature trouvée dans le message");
        }
        
        addMessage(
            decryptedMessage,
            "user",
            data.username,
            data.avatar,
            signatureStatus
        );
    } catch (error) {
        console.error("Erreur lors de la réception du message:", error);
        addMessage(
            "Message chiffré (impossible à déchiffrer)",
            "user",
            data.username,
            data.avatar
        );
    }
});

// Socket listener to receive the public key
socket.on("public_key", async (data) => {
    if (data.publicKey) {
        const importedPublicKey = await window.crypto.subtle.importKey(
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

// NOUVEAU écouteur socket pour recevoir les clés de vérification
socket.on("verify_key", async (data) => {
    if (data.verifyKey) {
        console.log("Réception de la clé de vérification de:", data.username);
        const importedVerifyKey = await importVerifyKey(data.verifyKey);
        verifyKeys[data.username] = importedVerifyKey;
        console.log("Clé de vérification importée pour:", data.username);
    }
});

// MODIFIER l'événement de connexion pour partager la clé de vérification
socket.on("connect", () => {
    // Demander les clés publiques comme avant
    setTimeout(() => {
        socket.emit("request_public_key");
        
        // NOUVEAU: Partager également notre clé de vérification
        if (rsaSignKeyPair) {
            shareVerifyKey();
        }
    }, 1000);
});

// Retrieve keys from session storage on page load
window.addEventListener("load", async function() {
    console.log("Chargement de la page, initialisation des clés");
    
    // Récupérer les clés existantes
    await retrieveKeys();
    
    // Si nous n'avons pas encore de paire de clés RSA, en générer une nouvelle
    if (!rsaKeyPair) {
        console.log("Génération d'une nouvelle paire de clés RSA...");
        rsaKeyPair = await generateRSAKeyPair();
        
        // Exporter et envoyer la clé publique
        const publicKeyExported = await window.crypto.subtle.exportKey("spki", rsaKeyPair.publicKey);
        const publicKeyBase64 = arrayBufferToBase64(publicKeyExported);
        socket.emit("public_key", { publicKey: publicKeyBase64 });
    }
    
    // Générer la paire de clés de signature à partir de la paire principale
    rsaSignKeyPair = await convertToSignKeyPair(rsaKeyPair);
    console.log("Paire de clés de signature générée avec succès");
});

sendButton.addEventListener("click", sendMessage);
messageInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") sendMessage();
});
updateUsernameButton.addEventListener("click", updateUsername);

// NOUVELLE FONCTION: Partager la clé publique de vérification avec logs
function shareVerifyKey() {
    if (rsaSignKeyPair) {
        console.log("Partage de la clé de vérification pour:", currentUsername);
        exportVerifyKey(rsaSignKeyPair.publicKey).then(verifyKeyBase64 => {
            console.log("Clé de vérification exportée:", verifyKeyBase64.substring(0, 20) + "...");
            socket.emit("verify_key", {
                username: currentUsername,
                verifyKey: verifyKeyBase64
            });
        });
    } else {
        console.log("Impossible de partager la clé de vérification: non générée");
    }
}

// NOUVELLE FONCTION: Utiliser la même paire de clés RSA pour le chiffrement et la signature
async function generateCombinedRSAKeyPair() {
    console.log("Génération d'une paire de clés RSA combinée pour chiffrement et signature...");
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: "SHA-256"
        },
        true,
        ["encrypt", "decrypt"]
    );
    
    // Créer une paire de clés pour la signature à partir de la même paire de clés
    const signKeyPair = await convertToSignKeyPair(keyPair);
    
    console.log("Paire de clés RSA combinée générée avec succès");
    return {
        encryptPair: keyPair,
        signPair: signKeyPair
    };
}

// NOUVELLE FONCTION: Convertir une clé RSA-OAEP en clé RSASSA-PKCS1-v1_5
async function convertToSignKeyPair(rsaKeyPair) {
    console.log("Conversion de la paire de clés pour la signature...");
    
    // Exporter les clés
    const publicKeyData = await window.crypto.subtle.exportKey(
        "spki", 
        rsaKeyPair.publicKey
    );
    
    const privateKeyData = await window.crypto.subtle.exportKey(
        "pkcs8", 
        rsaKeyPair.privateKey
    );
    
    // Importer les clés avec l'algorithme de signature
    const publicKey = await window.crypto.subtle.importKey(
        "spki",
        publicKeyData,
        {
            name: "RSASSA-PKCS1-v1_5",
            hash: "SHA-256"
        },
        true,
        ["verify"]
    );
    
    const privateKey = await window.crypto.subtle.importKey(
        "pkcs8",
        privateKeyData,
        {
            name: "RSASSA-PKCS1-v1_5",
            hash: "SHA-256"
        },
        true,
        ["sign"]
    );
    
    console.log("Conversion des clés réussie");
    return {
        publicKey: publicKey,
        privateKey: privateKey
    };
}

// SUPPRIMER les fonctions et écouteurs liés aux clés de vérification séparées
// Supprimez la fonction shareVerifyKey() et l'écouteur socket.on("verify_key", ...)


