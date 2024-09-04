// Caesar Cipher Functions

// Encryption Function
function caesarEncrypt(plaintext, shift) {
    let ciphertext = '';
    shift = shift % 26; // Normalize shift to be within 0-25

    for (let i = 0; i < plaintext.length; i++) {
        let char = plaintext.charCodeAt(i);

        if (char >= 65 && char <= 90) { // Uppercase letter
            char = ((char - 65 + shift) % 26 + 26) % 26 + 65;
        } else if (char >= 97 && char <= 122) { // Lowercase letter
            char = ((char - 97 + shift) % 26 + 26) % 26 + 97;
        }

        ciphertext += String.fromCharCode(char);
    }

    return ciphertext;
}

// Decryption Function
function caesarDecrypt(ciphertext, shift) {
    let plaintext = '';
    shift = shift % 26; // Normalize shift to be within 0-25

    for (let i = 0; i < ciphertext.length; i++) {
        let char = ciphertext.charCodeAt(i);

        if (char >= 65 && char <= 90) { // Uppercase letter
            char = ((char - 65 - shift) % 26 + 26) % 26 + 65;
        } else if (char >= 97 && char <= 122) { // Lowercase letter
            char = ((char - 97 - shift) % 26 + 26) % 26 + 97;
        }

        plaintext += String.fromCharCode(char);
    }

    return plaintext;
}

// Playfair Cipher Functions
function createPlayfairMatrix(key) {
    key = key.toLowerCase().replace(/[^a-z]/g, ''); // Remove non-alphabetic characters
    let matrix = [];
    let seen = {};
    key = key.replace(/j/g, 'i'); // Replace 'j' with 'i'

    for (let i = 0; i < key.length; i++) {
        if (!seen[key[i]] && key[i] !== 'j') {
            seen[key[i]] = true;
            matrix.push(key[i]);
        }
    }

    for (let i = 0; i < 26; i++) {
        let char = String.fromCharCode(97 + i);
        if (!seen[char] && char !== 'j') {
            matrix.push(char);
        }
    }

    return matrix;
}

function prepareText(text) {
    text = text.toLowerCase().replace(/[^a-z]/g, '');
    text = text.replace(/j/g, 'i');
    let result = '';

    for (let i = 0; i < text.length; i++) {
        result += text[i];
        if (i + 1 < text.length && text[i] === text[i + 1]) {
            result += 'x'; // Add 'x' between duplicate letters
        }
    }

    if (result.length % 2 !== 0) {
        result += 'x'; // Add 'x' if the length is odd
    }

    return result;
}

function getPlayfairPair(a, b, matrix, encrypt = true) {
    let posA = matrix.indexOf(a);
    let posB = matrix.indexOf(b);

    let rowA = Math.floor(posA / 5);
    let colA = posA % 5;
    let rowB = Math.floor(posB / 5);
    let colB = posB % 5;

    if (rowA === rowB) {
        // Same row: shift columns
        return encrypt ? 
            [matrix[rowA * 5 + (colA + 1) % 5], matrix[rowB * 5 + (colB + 1) % 5]] :
            [matrix[rowA * 5 + (colA - 1 + 5) % 5], matrix[rowB * 5 + (colB - 1 + 5) % 5]];
    }

    if (colA === colB) {
        // Same column: shift rows
        return encrypt ? 
            [matrix[((rowA + 1) % 5) * 5 + colA], matrix[((rowB + 1) % 5) * 5 + colB]] :
            [matrix[((rowA - 1 + 5) % 5) * 5 + colA], matrix[((rowB - 1 + 5) % 5) * 5 + colB]];
    }

    // Rectangle: swap columns
    return [matrix[rowA * 5 + colB], matrix[rowB * 5 + colA]];
}

function playfairEncrypt(plaintext, key) {
    let matrix = createPlayfairMatrix(key);
    plaintext = prepareText(plaintext);
    let ciphertext = '';

    for (let i = 0; i < plaintext.length; i += 2) {
        let pair = getPlayfairPair(plaintext[i], plaintext[i + 1], matrix, true);
        ciphertext += pair[0] + pair[1];
    }

    return ciphertext;
}

function playfairDecrypt(ciphertext, key) {
    let matrix = createPlayfairMatrix(key);
    ciphertext = prepareText(ciphertext);
    let plaintext = '';

    for (let i = 0; i < ciphertext.length; i += 2) {
        let pair = getPlayfairPair(ciphertext[i], ciphertext[i + 1], matrix, false);
        plaintext += pair[0] + pair[1];
    }

    return plaintext;
}


// Vigenère Cipher Functions

// Encryption Function
function vigenereEncrypt(plaintext, key) {
    let ciphertext = '';
    key = key.toLowerCase();
    let keyIndex = 0;

    for (let i = 0; i < plaintext.length; i++) {
        let char = plaintext.charCodeAt(i);

        if (char >= 65 && char <= 90) { // Uppercase letter
            char = ((char - 65 + (key.charCodeAt(keyIndex % key.length) - 97)) % 26) + 65;
            keyIndex++;
        } else if (char >= 97 && char <= 122) { // Lowercase letter
            char = ((char - 97 + (key.charCodeAt(keyIndex % key.length) - 97)) % 26) + 97;
            keyIndex++;
        }

        ciphertext += String.fromCharCode(char);
    }

    return ciphertext;
}

// Decryption Function
function vigenereDecrypt(ciphertext, key) {
    let plaintext = '';
    key = key.toLowerCase();
    let keyIndex = 0;

    for (let i = 0; i < ciphertext.length; i++) {
        let char = ciphertext.charCodeAt(i);

        if (char >= 65 && char <= 90) { // Uppercase letter
            char = ((char - 65 - (key.charCodeAt(keyIndex % key.length) - 97) + 26) % 26) + 65;
            keyIndex++;
        } else if (char >= 97 && char <= 122) { // Lowercase letter
            char = ((char - 97 - (key.charCodeAt(keyIndex % key.length) - 97) + 26) % 26) + 97;
            keyIndex++;
        }

        plaintext += String.fromCharCode(char);
    }

    return plaintext;
}






// Event Handlers for UI
$(document).ready(function() {
    // Caesar Cipher Encryption
    $("#caesarEncrypt").click(function() {
        let plaintext = $("#caesarPlaintextInput").val();
        let shift = parseInt($("#caesarKeyInput").val()) || 0; // Default to 0 if input is not a number
        if (plaintext) {
            $("#caesarOutput").text(caesarEncrypt(plaintext, shift));
        } else {
            $("#caesarOutput").text("Please enter plaintext.");
        }
    });

    // Caesar Cipher Decryption
    $("#caesarDecrypt").click(function() {
        let ciphertext = $("#caesarCiphertextInput").val();
        let shift = parseInt($("#caesarDecryptKeyInput").val()) || 0; // Default to 0 if input is not a number
        if (ciphertext) {
            $("#caesarOutput").text(caesarDecrypt(ciphertext, shift));
        } else {
            $("#caesarOutput").text("Please enter ciphertext.");
        }
    });

    // Playfair Cipher Encryption
    $("#playfairEncrypt").click(function() {
        let plaintext = $("#playfairPlaintextInput").val();
        let key = $("#playfairKeyInput").val();
        if (plaintext && key) {
            $("#playfairOutput").text(playfairEncrypt(plaintext, key));
        } else {
            $("#playfairOutput").text("Please enter both plaintext and key.");
        }
    });

    // Playfair Cipher Decryption
    $("#playfairDecrypt").click(function() {
        let ciphertext = $("#playfairCiphertextInput").val();
        let key = $("#playfairDecryptKeyInput").val();
        if (ciphertext && key) {
            $("#playfairOutput").text(playfairDecrypt(ciphertext, key));
        } else {
            $("#playfairOutput").text("Please enter both ciphertext and key.");
        }
    });

$("#vigenereEncrypt").click(function() {
        let plaintext = $("#vigenerePlaintextInput").val();
        let key = $("#vigenereKeyInput").val();
        if (plaintext && key) {
            $("#vigenereOutput").text(vigenereEncrypt(plaintext, key));
        } else {
            $("#vigenereOutput").text("Please enter both plaintext and key.");
        }
    });

    // Vigenère Cipher Decryption
    $("#vigenereDecrypt").click(function() {
        let ciphertext = $("#vigenereCiphertextInput").val();
        let key = $("#vigenereDecryptKeyInput").val();
        if (ciphertext && key) {
            $("#vigenereOutput").text(vigenereDecrypt(ciphertext, key));
        } else {
            $("#vigenereOutput").text("Please enter both ciphertext and key.");
        }
    });
});
