const bcrypt = require('bcryptjs');

// Hash password
const password = 'dev'; // Use your desired plain text password
const hashedPassword = bcrypt.hashSync(password, 10);

console.log('Hashed Password:', hashedPassword);

