require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

app.set('view engine', 'ejs');

const port = process.env.PORT || 3000;

const app = express();

const Joi = require("joi");

app.set('view engine', 'pug');

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



app.use(function (err, req, res, next) {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

app.use(function (req, res, next) {
    res.setHeader('X-Powered-By', 'Express');
    next();
});

app.get('/nosql-injection', async (req, res) => {
    var username = req.query.user;

    if (!username) {
        res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
        return;
    }
    console.log("user: " + username);

    const schema = Joi.string().max(20).required();
    const validationResult = schema.validate(username);

    //If we didn't use Joi to validate and check for a valid URL parameter below
    // we could run our userCollection.find and it would be possible to attack.
    // A URL parameter of user[$ne]=name would get executed as a MongoDB command
    // and may result in revealing information about all users or a successful
    // login without knowing the correct password.
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
        return;
    }

    const result = await userCollection.find({
        username: username
    }).project({
        username: 1,
        password: 1,
        _id: 1
    }).toArray();

    console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get('/members', (req, res) => {
    // If the user is not currently logged in, redirect to the home page
    if (!req.session.user) {
        res.redirect('/signin');
        return;
    }
    //make a random number between 1 and 3
    var num = Math.floor(Math.random() * 3) + 1;
    var html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Members Page</title>
  <!-- add Bootstrap stylesheet -->
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
</head>
<body>
<div class="container">
<div class="row justify-content-center">
<div class="col-md-6 text-center">
<h1> Welcome ${req.session.user.username}!</h1>
<h2> You are now a member of our site!</h2>
<h3> You can now see the members only content below!</h3>
<br>
        <img src="/00${num}.jpg" class="" width="400px" height="400px">
        <br>
        <form method="post" action="/signout">
          <button type="submit" class="btn btn-danger mt-3">Sign Out</button>
        </form>
        <!-- Add a home button -->
        <a href="/" class="btn btn-primary mt-3">Home</a>
      </div>
    </div>
  </div>
  <!-- add Bootstrap JavaScript -->
  <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/XvoG1uNus5LasEy" crossorigin="anonymous"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>
</body>
</html>
    `;
    res.send(html);
});




// Handle sign out form submission
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
app.get('/', (req, res) => {
    if (req.session.user) {
        // If the user is currently logged in, render the home page welcoming them and showing them the option to go to the members area and sign out
        res.send(`
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Welcome back ${req.session.user.username}!</title>
                <!-- add Bootstrap stylesheet -->
                <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
            </head>
            <body>
                <div class="container">
                    <div class="row justify-content-center">
                        <div class="col-md-6 text-center">
                            <h1>Welcome back ${req.session.user.username}!</h1>
                            <br>
                            <a href='/members' class="btn btn-primary">Members Area</a>
                            <br><br>
                            <form method="post" action="/signout">
                                <button type="submit" class="btn btn-danger">Sign Out</button>
                            </form>
                        </div>
                    </div>
                </div>
                <!-- add Bootstrap JavaScript -->
                <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/XvoG1uNus5LasEy" crossorigin="anonymous"></script>
                <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
                <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>
            </body>
            </html>
        `);
    } else {
        // If the user is not currently logged in, render the home page with the options to sign up or sign in
        res.send(`
        <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Sign in}!</title>
                <!-- add Bootstrap stylesheet -->
                <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
            </head>
            <body>
    <div class="container">
        <div class="row justify-content-center mt-5">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-body">
                        <h1 class="text-center mb-4">Welcome to the site!</h1>
                        <div class = "d-grid row justify-content-center gap-2" >
                            <a class="btn btn-primary" href="/signup">Sign Up</a>
                            <a class="btn btn-secondary" href="/signin">Sign In</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- add Bootstrap JavaScript -->
    
                <script src = "https://code.jquery.com/jquery-3.2.1.slim.min.js"
                integrity = "sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/XvoG1uNus5LasEy"
                crossorigin = "anonymous" > </script> <script src = "https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js"
                integrity = "sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q"
                crossorigin = "anonymous" > </script> <script src = "https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js"
                integrity = "sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl"
                crossorigin = "anonymous" > </script>
        </body></html>
`);
    }
});

// Render the sign up form
app.get('/signup', (req, res) => {
    let html = `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <title>Sign Up</title>
        <!-- add Bootstrap stylesheet -->
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
      </head>
      <body>
        <div class="container">
          <div class="row justify-content-center">
            <div class="col-md-6 text-center">
              <h1>Sign Up</h1>
              <form method='post' action='/signup'>
                <div class="form-group">
                  <label for='username'>Username:</label>
                  <input type='text' class="form-control" id='username' name='username' required>
                </div>
                <div class="form-group">
                  <label for='password'>Password:</label>
                  <input type='password' class="form-control" id='password' name='password' required>
                </div>
                <button type='submit' class="btn btn-primary">Sign Up</button>
              </form>
              <br>
              <a href="/" class="btn btn-secondary">Home</a>
            </div>
          </div>
        </div>
        <!-- add Bootstrap JavaScript -->
        <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/XvoG1uNus5LasEy" crossorigin="anonymous"></>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>
      </body>
    </html>
  `;
    res.send(html);
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

    // Create new user
    const newUser = {
        username: username,
        password: hashedPassword
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

    // Render the sign-in form
    var html = `<!DOCTYPE html>
  <html lang="en">
  <head>
    <meta charset="UTF-8">
    <title>Sign In</title>
    <!-- add Bootstrap stylesheet -->
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
  </head>
  <body>
    <div class="container">
      <div class="row justify-content-center">
        <div class="col-md-6 text-center">
          <h1>Sign In</h1>
          <form method='post' action='/signin'>
            <label for='username'>Username:</label>
            <input type='text' id='username' name='username' required><br><br>
            <label for='password'>Password:</label>
            <input type='password' id='password' name='password' required><br><br>
            <input type='submit' value='Sign In' class="btn btn-primary">
          </form>
          <br>
          <a href="/" class="btn btn-secondary">Home</a>
        </div>
      </div>
    </div>
    <!-- add Bootstrap JavaScript -->
    <script src="https://code.jquery.com/jquery-3.2.1.slim.min.js" integrity="sha384-KJ3o2DKtIkvYIK3UENzmM7KCkRr/rE9/Qpg6aAZGJwFDMVNA/XvoG1uNus5LasEy" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.12.9/umd/popper.min.js" integrity="sha384-ApNbgh9B+Y1QKtv3Rn7W3mgPxhU9K/ScQsAP7hUibX39j7fakFPskvXusvfa0b4Q" crossorigin="anonymous"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/js/bootstrap.min.js" integrity="sha384-JZR6Spejh4U02d8jOt6vLEHfe/JQGiRRSQQxSfFWpi1MquVdAyjUar5+76PVCmYl" crossorigin="anonymous"></script>
  </body>
  </html>
  `;
    res.send(html);
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
    res.redirect('/members');
});

app.get("*", (req, res) => {
    res.status(404);
    // res.send("Page not found - 404");
    //send a prettier html 404 error
    res.sendFile(__dirname + "/public/404.html");
})

// listen for requests :)
const listener = app.listen(process.env.PORT || 3000, () => {
    console.log(`Server started on port ${listener.address().port}`);
});