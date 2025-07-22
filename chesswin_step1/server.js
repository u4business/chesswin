const express = require('express');
const bcrypt = require('bcrypt');
const { ethers } = require('ethers');
const path = require('path');
const db = require('./db');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  if (!/^[a-zA-Z0-9_]{4,16}$/.test(username)) {
    return res.status(400).json({ message: 'Invalid username' });
  }

  const hashed = await bcrypt.hash(password, 10);
  const wallet = ethers.Wallet.createRandom();

  try {
    const exists = await db.query('SELECT * FROM users WHERE username=$1', [username]);
    if (exists.rows.length > 0) {
      return res.status(409).json({ message: 'Username taken' });
    }

    await db.query(
      'INSERT INTO users (username, password, wallet) VALUES ($1, $2, $3)',
      [username, hashed, wallet.address]
    );

    res.json({ wallet: wallet.address });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on ${port}`));