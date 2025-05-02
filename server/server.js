// server.js
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connecté')).catch(console.error);

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const tombSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  pseudo: String,
  message: String,
  date: String,
  x: Number,
  y: Number,
  views: { type: Number, default: 0 },
  reactions: {
    type: Map,
    of: Number,
    default: {}
  },
  reactedUsers: {
    type: Map,
    of: [String],
    default: {}
  }
});

const User = mongoose.model('User', userSchema);
const Tomb = mongoose.model('Tomb', tombSchema);

function verifyToken(req, res, next) {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Token requis' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Token invalide' });
  }
}

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  try {
    const existing = await User.findOne({ username });
    if (existing) return res.status(400).json({ message: 'Utilisateur déjà existant' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashed });
    res.status(201).json({ message: 'Utilisateur créé' });
  } catch (e) {
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(400).json({ message: 'Utilisateur non trouvé' });
  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(401).json({ message: 'Mot de passe incorrect' });
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.json({ token });
});

app.get('/tombs', async (req, res) => {
  const tombs = await Tomb.find();
  res.json(tombs);
});

// IMPORTANT : cette route doit venir AVANT /tombs/:id !
app.get('/tombs/top', async (req, res) => {
  try {
    let allTombs = await Tomb.find();
    const top = allTombs
      .filter(t => t._id && typeof t._id === 'object' && t.views !== undefined)
      .sort((a, b) => b.views - a.views)
      .slice(0, 10);
    res.json(top);
  } catch (e) {
    console.error("Erreur /tombs/top:", e);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.get('/tombs/:id', async (req, res) => {
  try {
    const tomb = await Tomb.findById(req.params.id);
    if (!tomb) return res.status(404).json({ message: 'Tombe introuvable' });
    tomb.views = (tomb.views || 0) + 1;
    await tomb.save();
    res.json(tomb);
  } catch (e) {
    console.error("Erreur /tombs/:id:", e);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.post('/tombs', verifyToken, async (req, res) => {
  const { pseudo, message, date, x, y } = req.body;
  try {
    const tomb = await Tomb.create({ userId: req.userId, pseudo, message, date, x, y });
    res.status(201).json(tomb);
  } catch (e) {
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

app.post('/tombs/:id/react', verifyToken, async (req, res) => {
  const { emoji } = req.body;
  const userId = req.userId;
  if (!emoji) return res.status(400).json({ message: 'Emoji requis' });
  try {
    const tomb = await Tomb.findById(req.params.id);
    if (!tomb) return res.status(404).json({ message: 'Tombe introuvable' });
    const existing = tomb.reactedUsers.get(emoji) || [];
    if (existing.includes(userId)) return res.status(400).json({ message: 'Déjà réagi avec cet emoji' });

    tomb.reactions.set(emoji, (tomb.reactions.get(emoji) || 0) + 1);
    tomb.reactedUsers.set(emoji, [...existing, userId]);
    await tomb.save();
    res.json({ message: 'Réaction ajoutée' });
  } catch (e) {
    console.error("Erreur /react:", e);
    res.status(500).json({ message: 'Erreur serveur' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur lancé sur le port ${PORT}`));
app.use(express.static('public'));
