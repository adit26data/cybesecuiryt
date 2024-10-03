const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');

// Setup SQLite Database
const db = new sqlite3.Database('./users.db', (err) => {
  if (err) {
    console.error("Error opening database: " + err.message);
  } else {
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT,
        encryption_key TEXT,
        cipher TEXT
      )
    `, (err) => {
      if (err) {
        console.error("Error creating users table: " + err.message);
      }
    });
  }
});

// Initialize Express app
const app = express();

// Middleware to parse incoming requests
app.use(bodyParser.json());
app.use(express.static(__dirname)); // Serve static files (HTML, CSS, etc.)

// Caesar Cipher encryption function
function caesarCipher(text, key) {
  let result = '';
  for (let i = 0; i < text.length; i++) {
    let char = text[i];
    if (char.match(/[a-zA-Z0-9]/i)) {
      let code = text.charCodeAt(i);
      // Uppercase letters
      if (code >= 65 && code <= 90) {
        char = String.fromCharCode(((code - 65 + key) % 26) + 65);
      }
      // Lowercase letters
      else if (code >= 97 && code <= 122) {
        char = String.fromCharCode(((code - 97 + key) % 26) + 97);
      } else if (code >= 48 && code <= 57) {
        char = String.fromCharCode(((code - 48 + key) % 10) + 48);
      }
    }
    result += char;
  }
  return result;
}

// Vigenere Cipher encryption function
function vigenereCipher(text, key) {
  let result = '';
  key = key.toUpperCase();
  for (let i = 0, j = 0; i < text.length; i++) {
    let char = text[i];
    if (char.match(/[a-zA-Z0-9]/i)) {
      let code = text.charCodeAt(i);
      let keyChar = key[j % key.length];
      if (code >= 65 && code <= 90) {
        char = String.fromCharCode(((code - 65 + keyChar.charCodeAt(0) - 65) % 26) + 65);
        j++;
      } else if (code >= 97 && code <= 122) {
        char = String.fromCharCode(((code - 97 + keyChar.charCodeAt(0) - 65) % 26) + 97);
        j++;
      } else if (code >= 48 && code <= 57) {
        char = String.fromCharCode(((code - 48 + keyChar.charCodeAt(0) - 48) % 10) + 48);
        j++;
      }
    }
    result += char;
  }
  return result;
}

// Playfair Cipher functions (as provided in the previous response)
function generatePlayfairMatrix(key) {
  const alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'; // Excluding 'J'
  key = key.toUpperCase().replace(/J/g, 'I'); // Replace J with I in the key
  let matrix = [];
  let usedLetters = new Set();

  for (let char of key) {
    if (!usedLetters.has(char) && alphabet.includes(char)) {
      matrix.push(char);
      usedLetters.add(char);
    }
  }

  for (let char of alphabet) {
    if (!usedLetters.has(char)) {
      matrix.push(char);
      usedLetters.add(char);
    }
  }

  let playfairMatrix = [];
  for (let i = 0; i < 5; i++) {
    playfairMatrix.push(matrix.slice(i * 5, i * 5 + 5));
  }

  return playfairMatrix;
}

function findPosition(matrix, char) {
  for (let i = 0; i < 5; i++) {
    for (let j = 0; j < 5; j++) {
      if (matrix[i][j] === char) {
        return [i, j];
      }
    }
  }
}

function processDigraphs(text) {
  text = text.toUpperCase().replace(/J/g, 'I'); // Replace J with I
  let result = '';
  for (let i = 0; i < text.length; i++) {
    let char1 = text[i];
    let char2 = (i + 1 < text.length && text[i + 1] !== char1) ? text[i + 1] : 'X'; // Handle repeated letters or final odd letters
    result += char1 + char2;
    i += (char2 !== 'X') ? 1 : 0; // Skip next character if it was not inserted
  }
  return result;
}

function playfairEncrypt(plaintext, key) {
  const matrix = generatePlayfairMatrix(key);
  const preparedText = processDigraphs(plaintext);
  let encryptedText = '';

  for (let i = 0; i < preparedText.length; i += 2) {
    const char1 = preparedText[i];
    const char2 = preparedText[i + 1];
    const [row1, col1] = findPosition(matrix, char1);
    const [row2, col2] = findPosition(matrix, char2);

    if (row1 === row2) {
      encryptedText += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5];
    } else if (col1 === col2) {
      encryptedText += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2];
    } else {
      encryptedText += matrix[row1][col2] + matrix[row2][col1];
    }
  }

  return encryptedText;
}

// Function to encrypt based on the selected cipher
function encrypt(text, key, cipher) {
  switch (cipher) {
    case 'caesar':
      return caesarCipher(text, parseInt(key));
    case 'vigenere':
      return vigenereCipher(text, key);
    case 'playfair':
      return playfairEncrypt(text, key);
    default:
      throw new Error('Unknown cipher');
  }
}

// Signup Route
app.post('/signup', (req, res) => {
  const { username, password, key, cipher } = req.body;

  if (!username || !password || !key || !cipher) {
    res.status(400).json({ message: 'Please provide all fields.' });
    return;
  }

  const encryptedPassword = encrypt(password, key, cipher);
  const encryptedKey = encrypt(key, key, cipher); // Encrypt the key as well
  const encryptedCipher = encrypt(cipher, key, cipher); // Encrypt the cipher choice

  // Insert user data into database
  db.run('INSERT INTO users (username, password, encryption_key, cipher) VALUES (?, ?, ?, ?)', 
    [username, encryptedPassword, encryptedKey, encryptedCipher], function(err) {
    if (err) {
      console.error("Signup Error: " + err.message);
      res.status(500).json({ message: 'Signup failed. Username might already exist.' });
    } else {
      res.status(200).json({ message: 'Signup successful!' });
    }
  });
});

// Login Route
app.post('/login', (req, res) => {
  const { username, password, key, cipher } = req.body;

  if (!username || !password || !key || !cipher) {
    res.status(400).json({ message: 'Please provide all fields.' });
    return;
  }

  const encryptedPassword = encrypt(password, key, cipher);
  const encryptedKey = encrypt(key, key, cipher); // Encrypt the key
  const encryptedCipher = encrypt(cipher, key, cipher); // Encrypt the cipher choice

  // Check if user exists in database
  db.get('SELECT * FROM users WHERE username = ? AND password = ? AND encryption_key = ? AND cipher = ?', 
    [username, encryptedPassword, encryptedKey, encryptedCipher], (err, row) => {
    if (err) {
      console.error("Login Error: " + err.message);
      res.status(500).json({ message: 'Login failed due to server error.' });
    } else if (row) {
      res.status(200).json({ message: 'Login successful!' });
    } else {
      res.status(401).json({ message: 'Invalid username, password, key, or cipher.' });
    }
  });
});

// Serve HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start the server
app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
