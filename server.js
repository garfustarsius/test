const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const db = require('./db');

const app = express();
const port = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'garfustarsius',
  resave: false,
  saveUninitialized: true,
}));

// Set EJS as the view engine
app.set('view engine', 'ejs');

// Serve static files
app.use(express.static(__dirname + '/public'));

// Routes
app.get('/', (req, res) => {
  res.render('login');
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

    // Check if the password meets the minimum length requirement
    if (password.length < 6) {
      return res.render('register', { error: 'Password must be at least 6 characters long' });
    }
  

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Insert the user into the database
  db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], (err) => {
    if (err) {
      return res.render('register', { error: 'User already exists' });
    }
    res.render('registration-success');
  });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // Check if the user exists in the database
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.render('login', { error: 'Invalid username or password' });
    }

    req.session.userId = user.id;
    res.redirect('/dashboard');
  });
});

app.get('/dashboard', (req, res) => {
  if (!req.session.userId) {
    return res.redirect('/');
  }

  // Fetch the user's data from the database here
  

  db.get('SELECT username FROM users WHERE id = ?', [req.session.userId], (err, user) => {
    if (err) {
      console.error('Error fetching user data:', err);
      return res.redirect('/');
    }

    res.render('dashboard', { username: user.username });
  });
});


// Logout route
app.get('/logout', (req, res) => {
  // Destroy the user's session
  req.session.destroy((err) => {
    if (err) {
      console.error('Error destroying session:', err);
    }
    res.redirect('/');
  });
});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
