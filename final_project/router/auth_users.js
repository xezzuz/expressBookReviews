const express = require('express');
const jwt = require('jsonwebtoken');
let books = require("./booksdb.js");
const regd_users = express.Router();

let users = [];

const isValid = (username) => {
    return users.some(user => user.username === username);
};

const authenticatedUser = (username, password) => {
    return users.some(user => user.username === username && user.password === password);
};

regd_users.post("/login", (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: "Username and password are required" });
    }

    if (!authenticatedUser(username, password)) {
        return res.status(401).json({ message: "Invalid username or password" });
    }

    const accessToken = jwt.sign({ username }, 'secretKey', { expiresIn: '1h' });

    // return res.status(200).json({ message: "Login successful", token: accessToken });
    return res.status(200).json({ message: "Customer successfully logged in", token: accessToken });
});

regd_users.put("/auth/review/:isbn", (req, res) => {
    const { isbn } = req.params;
    const { review } = req.body;
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: "Authorization header is missing" });
    }

    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, 'secretKey');
        const username = decoded.username;

        if (!books[isbn]) {
            return res.status(404).json({ message: "Book not found" });
        }

        if (!books[isbn].reviews) {
            books[isbn].reviews = {};
        }
        books[isbn].reviews[username] = review;

        return res.status(200).json({ message: "Review added/updated successfully" });
    } catch (err) {
        return res.status(403).json({ message: "Invalid token" });
    }
});

regd_users.delete("/auth/review/:isbn", (req, res) => {
    const { username } = req.user;  // Access the decoded user data from the token
    const { isbn } = req.params;

    // Check if the book exists
    if (!books[isbn]) {
        return res.status(404).json({ message: "Book not found" });
    }

    // Check if the user has previously reviewed the book
    if (!books[isbn].reviews || !books[isbn].reviews[username]) {
        return res.status(400).json({ message: "Review not found for this user" });
    }

    // Delete the review
    delete books[isbn].reviews[username];

    return res.status(200).json({ message: "Review deleted successfully" });
});

module.exports.authenticated = regd_users;
module.exports.isValid = isValid;
module.exports.users = users;
