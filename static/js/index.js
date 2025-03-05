const socket = io();
const chatMessages = document.getElementById("chat-messages");
const messageInput = document.getElementById("message-input");
const sendButton = document.getElementById("send-button");
const currentUsernameSpan = document.getElementById("current-username");
const usernameInput = document.getElementById("username-input");
const updateUsernameButton = document.getElementById("update-username-button");


let currentUsername = "";

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
    if (e.key === "Enter") sendMessage();
});
updateUsernameButton.addEventListener("click", updateUsername);

// Fonction pour convertir base64 en array buffer
function base64ToArrayBuffer(base64) {
    var binary_string = window.atob(base64);
    var len = binary_string.length;
    var bytes = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
}

// Fonction pour déchiffrer le message avec AES (mode CBC)
async function aesDecrypt(encryptedMessage, keyBase64, ivBase64) {
    const key = await crypto.subtle.importKey(
        "raw",
        base64ToArrayBuffer(keyBase64),
        { name: "AES-CBC" },
        false,
        ["decrypt"]
    );

    const iv = base64ToArrayBuffer(ivBase64);
    const encryptedData = base64ToArrayBuffer(encryptedMessage);

    try {
        const decryptedData = await crypto.subtle.decrypt(
            { name: "AES-CBC", iv: iv },
            key,
            encryptedData
        );
        const decoder = new TextDecoder();
        return decoder.decode(decryptedData);
    } catch (err) {
        console.error("Erreur lors du déchiffrement : ", err);
        return null;
    }
}


function sendMessage() {
    const message = messageInput.value.trim();
    if (message) {
        socket.emit("send_message", { message });
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
        messageElement.appendChild(avatarImg);

        const contentDiv = document.createElement("div");
        contentDiv.className = "message-content";

        const usernameDiv = document.createElement("div");
        usernameDiv.className = "message-username";
        usernameDiv.textContent = username;
        contentDiv.appendChild(usernameDiv);

        const messageText = document.createElement("div");
        messageText.textContent = message;
        contentDiv.appendChild(messageText);

        messageElement.appendChild(contentDiv);
    } else {
        messageElement.className = "system-message";
        messageElement.textContent = message;
    }
    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}
