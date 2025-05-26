const bcrypt = require('bcryptjs');

// Hash password
const password = 'example_password'; // Use your desired plain text password
const hashedPassword = bcrypt.hashSync(password, 10);

console.log('Hashed Password:', hashedPassword);

