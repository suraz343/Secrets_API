import express from "express";
import bodyParser from "body-parser";
import mysql from 'mysql2';
import bcrypt from 'bcrypt';
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";


const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
  secret : "TOPSECRET",
  resave: false,
  saveUninitialized: true,
}));

app.use(passport.initialize());
app.use(passport.session());



// Creating a connection with MySQL
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_SECRETS
});

db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log("Connected to the database");
});

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets",(req,res) => {
  if (req.isAuthenticated()){
    res.render("secrets.ejs");
  }
  else{
    res.redirect("/login")
  }

});

app.post("/register", async (req, res) => {
  


});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const [rows] = await db.promise().query("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length > 0) {
      const user = rows[0];
      const match = await bcrypt.compare(password, user.password);
      if (match) {
        res.render("secrets.ejs");
      } else {
        res.status(401).send('Invalid credentials');
      }
    } else {
      res.status(401).send('Invalid credentials');
    }
  } catch (err) {
    console.error(err);
    res.status(500).send('Error querying the database.');
  }
});

passport.use(new Strategy(async function verify(username, password, cb){
  try {
    // Check if the email already exists
    const [rows] = await db.promise().query("SELECT * FROM users WHERE email = ?", [username]);
    if (rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      // Hash the password
      const hash = await bcrypt.hash(password, saltRounds);
      
      // Insert new user
      const [result] = await db.promise().query("INSERT INTO users (email, password) VALUES (?, ?)", [email, hash]);
      console.log(result);
      res.render("secrets.ejs");
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Error interacting with the database.");
  }

}))

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
