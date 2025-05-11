const express = require('express');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const bcrypt = require('bcrypt');

const app = express();

// In-memory user store (for demo; use a database in production)
const users = [];

// Express settings
app.use(express.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

// Serialize/deserialize
passport.serializeUser((user, done) => done(null, user.email));
passport.deserializeUser((email, done) => {
  const user = users.find(u => u.email === email);
  done(null, user);
});

// Local Strategy
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
  const user = users.find(u => u.email === email);
  if (!user) return done(null, false, { message: 'User not found' });
  const match = await bcrypt.compare(password, user.password);
  return match ? done(null, user) : done(null, false, { message: 'Incorrect password' });
}));

// Google OAuth Strategy
passport.use(new GoogleStrategy({
  clientID: 'GOOGLE_CLIENT_ID',
  clientSecret: 'GOOGLE_CLIENT_SECRET',
  callbackURL: '/auth/google/callback'
}, (accessToken, refreshToken, profile, done) => {
  let user = users.find(u => u.email === profile.emails[0].value);
  if (!user) {
    user = { email: profile.emails[0].value, name: profile.displayName };
    users.push(user);
  }
  return done(null, user);
}));

// Facebook OAuth Strategy
passport.use(new FacebookStrategy({
  clientID: 'FACEBOOK_APP_ID',
  clientSecret: 'FACEBOOK_APP_SECRET',
  callbackURL: '/auth/facebook/callback',
  profileFields: ['id', 'displayName', 'emails']
}, (accessToken, refreshToken, profile, done) => {
  const email = profile.emails?.[0]?.value || `${profile.id}@facebook.com`;
  let user = users.find(u => u.email === email);
  if (!user) {
    user = { email, name: profile.displayName };
    users.push(user);
  }
  return done(null, user);
}));

// Routes
app.get('/', (req, res) => {
  res.send(`<h2>Welcome</h2>${req.user ? `<p>Hello, ${req.user.name || req.user.email}</p><a href="/logout">Logout</a>` : `<a href="/login.html">Login</a>`}`);
});

// Local login
app.post('/login', passport.authenticate('local', {
  successRedirect: '/',
  failureRedirect: '/login.html'
}));

// Google routes
app.get('/auth/google', passport.authenticate('google', { scope: ['email', 'profile'] }));
app.get('/auth/google/callback', passport.authenticate('google', {
  successRedirect: '/',
  failureRedirect: '/login.html'
}));

// Facebook routes
app.get('/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/auth/facebook/callback', passport.authenticate('facebook', {
  successRedirect: '/',
  failureRedirect: '/login.html'
}));

// Logout
app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// Register route (optional for testing)
app.get('/register', (req, res) => {
  res.send(`<form method="POST"><input name="email" required/><input name="password" type="password" required/><button type="submit">Register</button></form>`);
});
app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (users.find(u => u.email === email)) return res.send('User already exists');
  const hashed = await bcrypt.hash(password, 10);
  users.push({ email, password: hashed });
  res.redirect('/login.html');
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
To capture login data
