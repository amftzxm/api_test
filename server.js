const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const { findUser, addUser } = require('./users');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'key1234';

app.use(bodyParser.json());

app.post('/api/register', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }

    if (findUser(username)) {
        return res.status(400).json({ message: 'User already exists' });
    }

    addUser(username, password);
    res.status(201).json({ message: 'User registered successfully' });
});

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = findUser(username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ token });
});

const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        return res.sendStatus(403); 
    }

    const token = authHeader.split(' ')[1];

    if (!token) {
        return res.sendStatus(403);
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.get('/protected', authenticateJWT, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});


app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
