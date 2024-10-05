const bcrypt = require('bcryptjs');

const users = [];

const findUser = (username) => users.find(user => user.username === username);

const addUser = (username, password) => {
    const hashedPassword = bcrypt.hashSync(password, 10);
    users.push({ username, password: hashedPassword });
};

module.exports = { findUser, addUser };
