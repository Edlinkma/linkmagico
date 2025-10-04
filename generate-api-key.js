const crypto = require('crypto');

function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}

const newApiKey = generateApiKey();
console.log(`Sua nova chave de API é: ${newApiKey}`);

