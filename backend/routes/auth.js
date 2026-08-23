import express from 'express';
import pool from '../db.js';
import { encryptionSync, decryptionSync } from '../passwordCrypto.js';

const router = express.Router();

const SECRET_KEY = process.env.PASSWORD_SECRET_KEY;
const SALT_ROUND = Number(process.env.PASSWORD_SALT_ROUND) || 12;

if (!SECRET_KEY) {
  throw new Error('PASSWORD_SECRET_KEY is missing from your .env file');
}

router.post('/signup', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: 'name, email, and password are all required' });
  }

  let client;
  try {
    client = await pool.connect();

    const existing = await client.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const encryptedPassword = encryptionSync(password, SECRET_KEY, SALT_ROUND);

    const result = await client.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id, name, email',
      [name, email, encryptedPassword]
    );

    res.status(201).json({ user: result.rows[0] });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  } finally {
    client?.release();
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  let client;
  try {
    client = await pool.connect();

    const result = await client.query(
      'SELECT id, name, email, password FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];

    let decryptedPassword;
    try {
      decryptedPassword = decryptionSync(user.password, SECRET_KEY, SALT_ROUND);
    } catch (err) {
      console.error('Password decryption error:', err);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    if (decryptedPassword !== password) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    res.json({ user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Something went wrong. Please try again.' });
  } finally {
    client?.release();
  }
});

export default router;
