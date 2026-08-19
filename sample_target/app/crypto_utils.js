const crypto = require("crypto");

// Genera un par de claves RSA de 2048 bits.
function generateSigningKey() {
  return crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
}

// Hashea password con MD5 y devuelve el digest en hexadecimal.
function hashPassword(password) {
  return crypto.createHash("md5").update(password).digest("hex");
}

// Cifra data con AES-128-GCM usando key e iv.
function encryptPayloadWeak(key, iv, data) {
  const cipher = crypto.createCipheriv("aes-128-gcm", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

// Cifra data con AES-256-GCM usando key e iv.
function encryptPayload(key, iv, data) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

module.exports = { generateSigningKey, hashPassword, encryptPayloadWeak, encryptPayload };
