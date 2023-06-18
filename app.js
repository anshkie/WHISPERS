//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const md5 = require("md5");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const LocalStrategy = require("passport-local");
const GoogleStrategy = require("passport-google-oidc");
const app = express();

console.log(process.env.API_KEY);
//const encrypt = require("mongoose-encryption");

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: "Jai mata di",
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());
mongoose.connect("mongodb://localhost:27017/userDB", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  family: 4,
});
let db;


const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId:String,
  secret:String

});

/*userSchema.plugin(encrypt, {
  secret: process.env.SECRET,
  encryptedFields: ["password"],
});*/
userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);
passport.use(new LocalStrategy(User.authenticate()));
//const db = mongoose.connection;
//db.on('error', console.error.bind(console, 'MongoDB connection error:'));
// use static serialize and deserialize of model for passport session support
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env["CLIENT_ID"],
      clientSecret: process.env["CLIENT_SECRET"],
      callbackURL: "http://localhost:3000/auth/google/secret",
    },
    
    function (issuer, profile, cb) {
      db.get(
        "SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?",
        [issuer, profile.id],
        function (err, cred) {
          if (err) {
            return cb(err);
          }
          if (!cred) {
            // The Google account has not logged in to this app before.  Create a
            // new user record and link it to the Google account.
            db.run(
              "INSERT INTO users (name) VALUES (?)",
              [profile.displayName],
              function (err) {
                if (err) {
                  return cb(err);
                }

                var id = this.lastID;
                db.run(
                  "INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)",
                  [id, issuer, profile.id],
                  function (err) {
                    if (err) {
                      return cb(err);
                    }
                    var user = {
                      id: id.toString(),
                      name: profile.displayName,
                    };
                    return cb(null, user);
                  }
                );
              }
            );
          } else {
            // The Google account has previously logged in to the app.  Get the
            // user record linked to the Google account and log the user in.
            db.get(
              "SELECT * FROM users WHERE id = ?",
              [cred.user_id],
              function (err, user) {
                if (err) {
                  return cb(err);
                }
                if (!user) {
                  return cb(null, false);
                }
                return cb(null, user);
              }
            );
          }
        }
      );
    }
  )
);

app.get("/", function (req, res) {
  res.render("home");
});

app.get("/login", function (req, res) {
  res.render("login");
});

app.get("/register", function (req, res) {
  res.render("register");
});
app.get("/logout", function (req, res, next) {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async function (req, res) {
    /*if (req.isAuthenticated()) {
      res.render("secrets");
    } else {
      res.redirect("/login");
    }*/
    
   
      if (req.isAuthenticated()) {
        try {
          const foundUsers = await User.find({ secret: { $ne: null } }).exec();
          res.render("secrets", { usersWithSecrets: foundUsers });
        } catch (err) {
          console.log(err);
          res.status(500).send("Internal Server Error");
        }
      } else {
        res.redirect("/login");
      }
    });
    
    
  

app.get("/submit",function(req,res){
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});
app.post("/submit", async function (req, res) {
  const submits = req.body.secret;
  try {
    const foundUser = await User.findById(req.user.id).exec();
    if (foundUser) {
      foundUser.secret = submits;
      await foundUser.save();
      res.redirect("/secrets");
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Internal Server Error");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);
app.get(
  "/auth/google/secret",
  passport.authenticate("google", {
    failureRedirect: "/login",
    failureMessage: true,
  }),
  function (req, res) {
    res.redirect("/");
  }
);

app.post("/register", async function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
  /* try {
    const newUser = new User({
      email: req.body.username,
      password: md5(req.body.password),
    });
    await newUser.save();
    res.render("secrets");
  } catch (err) {
    console.log(err);
  }*/
});
app.post("/login", async function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});
/* const password = req.body.password;
  const username = req.body.username;
  try {
    const foundUser = await User.findOne({ email: username });
    if (foundUser && foundUser.password === password) {
      res.render("secrets");
    } else {
      res.send("Incorrect username or password");
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Internal Server Error");
  }*/

app.listen(3000, function () {
  console.log("Server started at port 3000");
});
//1 level=Password
//2 level=Database encryption
//3 level=Hashing Password