require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const url = require('url');

const app = express();

app.set('view engine', 'ejs');

const Joi = require("joi");

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {
  database
} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({
  extended: false
}));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}?retryWrites=true`,
  crypto: {
    secret: mongodb_session_secret
  }
})

app.use(session({
  secret: node_session_secret,
  store: mongoStore,
  saveUninitialized: false,
  resave: true,
  cookie: {
    maxAge: 60 * 60 * 1000 // 1 hour in milliseconds
  }
}));


const navLinks = [
  { label: "Home", path: "/", },
  { label: "Sign Up", path: "/signup" },
  { label: "Sign In", path: "/signin" },
  { label: "Members", path: "/members" },
  { label: "Admin", path: "/admin" }
];


function isValidSession(req) {
  console.log("checking session")
  if (req.session.user) {
    return true;
  }
  return false;
}

function isAdmin(req) {
  if (req.session.user.user_type == 'admin') {
    return true;
  }
  return false;
}

function adminAuthorization(req, res) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("notAuthorized", { user: req.session.user, navLinks: navLinks, currentUrl: url.parse(req.url).pathname });
    return false;
  }
  else {
    return true;
  }
}

app.use(function (err, req, res, next) {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// app.use(function (req, res, next) {
//   res.setHeader('X-Powered-By', 'Express');
//   next();
// });

app.get('/admin', async (req, res) => {
  if (!isValidSession(req)) {
    res.redirect('/signin');
    return;
  }
  console.log("checking admin")
  userIsAdmin = adminAuthorization(req, res);
  console.log("admin: " + userIsAdmin)
  if (userIsAdmin) {
    console.log("admin found")
    const result = await userCollection.find({}).toArray();
    res.render('admin', { user: req.session.user, users: result, navLinks: navLinks, currentUrl: url.parse(req.url).pathname });
  }
});



app.get('/', (req, res) => {
  res.render("index", { user: req.session.user, navLinks: navLinks, currentUrl: url.parse(req.url).pathname });
});

app.get('/members', (req, res) => {
  // If the user is not currently logged in, redirect to the home page
  if (!req.session.user) {
    res.redirect('/signin');
    return;
  }
  //make a random number between 1 and 3
  var num = Math.floor(Math.random() * 3) + 1;
  res.render('members', { user: req.session.user, num: num, navLinks: navLinks, currentUrl: url.parse(req.url).pathname });
});


// Handle sign out form submission
app.post('/signout', (req, res) => {
  // Clear the user session and redirect to home page
  req.session.user = null;
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
      return res.redirect('/');
    }
    res.clearCookie('connect.sid');
    res.redirect('/');
    return
  });
});





app.use(express.static(__dirname + "/public"));

// Render the home page with the options to sign up or sign in if not currently logged in



// Render the sign up form
app.get('/signup', (req, res) => {
  res.render('sign up', { user: req.session.user, navLinks: navLinks, currentUrl: url.parse(req.url).pathname });
});


// Handle sign up form submission
app.post('/signup', async (req, res) => {
  const {
    username,
    password
  } = req.body;

  // Validate input
  const schema = Joi.object({
    username: Joi.string().alphanum().min(3).max(20).required(),
    password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')).required()
  });
  const validationResult = schema.validate({
    username,
    password
  });
  if (validationResult.error) {
    res.status(400).send(`Invalid username or password. <a href="/">Go back to home</a>`);
    return;
  }

  // Check if username already exists
  const existingUser = await userCollection.findOne({
    username: username
  });
  if (existingUser) {
    res.status(409).send(`Username already exists. <a href="/">Go back to home</a>`);
    return;
  }

  // Hash password
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  var newDate = new Date();
  // Create new user
  const newUser = {
    username: username,
    password: hashedPassword,
    user_type: 'user',
    createdAt: newDate.toLocaleDateString() + " @ " + newDate.toLocaleTimeString()
  };
  await userCollection.insertOne(newUser);

  // Log in user
  req.session.user = newUser;

  // Redirect to members area
  res.redirect('/members');
});




// Sign in page
app.get('/signin', (req, res) => {
  // If the user is already logged in, redirect to the members page
  if (req.session.user) {
    res.redirect('/members');
    return;
  }
  res.render("sign in", { user: req.session.user, navLinks: navLinks, currentUrl: url.parse(req.url).pathname });
});


// Handle sign in form submission
app.post('/signin', async (req, res) => {
  const {
    username,
    password
  } = req.body;

  // Validate input
  const schema = Joi.object({
    username: Joi.string().alphanum().min(3).max(20).required(),
    password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')).required()
  });
  const validationResult = schema.validate({
    username,
    password
  });
  if (validationResult.error) {
    res.status(400).send(`Invalid username or password. <a href="/">Go back to home</a>`);
    return;
  }

  // Check if username exists
  const existingUser = await userCollection.findOne({
    username: username
  });
  if (!existingUser) {
    res.status(401).send('Invalid username or password. <a href="/">Go back to home</a>');
    return;
  }

  // Validate password
  const validPassword = await bcrypt.compare(password, existingUser.password);
  if (!validPassword) {
    res.status(401).send('Invalid username or password. <a href="/">Go back to home</a>');
    return;
  }

  // Log in user
  req.session.user = existingUser;

  // Redirect to members area
  if (existingUser.user_type === 'admin') {
    res.redirect('/admin');
    return;
  }
  res.redirect('/members');
});

app.post('/promoteUser', function (req, res) {
  const username = req.body.username;
  const filter = { username };
  const update = { $set: { user_type: "admin" } };

  console.log(username);
  userCollection.updateOne(filter, update)
    .then(result => {
      console.log(`Updated ${result.modifiedCount} document.`);
    })
    .catch(err => console.error(`Failed to update document: ${err}`));

  res.redirect('/admin');
});

app.post('/demoteUser', function (req, res) {
  const username = req.body.username;
  const filter = { username };
  const update = { $set: { user_type: "user" } };

  console.log(username);
  userCollection.updateOne(filter, update)
    .then(result => {
      console.log(`Updated ${result.modifiedCount} document.`);
    })
    .catch(err => console.error(`Failed to update document: ${err}`));

  res.redirect('/admin');
});


app.get("*", (req, res) => {
  res.status(404);
  // res.send("Page not found - 404");
  //send a prettier html 404 error
  res.render('404', { navLinks: navLinks, currentUrl: url.parse(req.url).pathname });
})

// listen for requests :)
const listener = app.listen(process.env.PORT || 3000, () => {
  console.log(`Server started on port ${listener.address().port}`);
});