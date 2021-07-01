//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const encrypt = require("mongoose-encryption")
// const md5 = require("md5");
// const bcrypt = require("bcrypt")
// const saltRounds = 10;
const session = require("express-session")
const passport = require("passport")
const passportLocalMongoose = require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate')

mongoose.connect('mongodb://localhost:27017/userDB', { useNewUrlParser: true, useUnifiedTopology: true, useFindAndModify: false })
mongoose.set("useCreateIndex", true)

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }))


app.use(session({
    secret: 'A simple secret',
    resave: false,
    saveUninitialized: true,
    // cookie: { secure: true }
}))

app.use(passport.initialize());
app.use(passport.session())

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: String
});

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate);
// const secret = process.env.SECRET;
// userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });

const User = new mongoose.model('User', userSchema);

// use static authenticate method of model in LocalStrategy
passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        // console.log(profile)
        User.findOrCreate({ googleId: profile.id }, function (err, user) {
            return cb(err, user);
        });
    }
));

passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
},
    function (accessToken, refreshToken, profile, done) {
        // console.log(profile);
        User.findOrCreate({ facebookId: profile.id }, function (err, user) {
            if (err) { return done(err); }
            done(null, user);
        });
    }
));

app.get('/', (req, res) => {
    res.render("home");
});

app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] }));

app.get('/auth/google/secrets',
    passport.authenticate('google', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });

app.get('/auth/facebook', passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    });

app.route("/login")
    .get((req, res) => {
        res.render("login");
    })
    .post((req, res) => {
        let user = new User({
            username: req.body.username,
            password: req.body.password
        })
        req.login(user, (err) => {
            if (err) {
                console.log(err)
            } else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets")
                })
            }
        })
    })

app.get("/secrets", (req, res) => {
    User.find({"secret": {$ne: null}}, (err, foundSecrets) => {
        if (err) {
            console.log(err)
        } else {
            res.render("secrets", {secrets: foundSecrets})
        }
    })
})

app.get("/logout", (req, res) => {
    req.logOut()
    res.redirect("/")
})
app.route('/register')
    .get((req, res) => {
        res.render("register")
    })
    .post((req, res) => {
        User.register({ username: req.body.username }, req.body.password, function (err, user) {
            if (err) {
                console.log(err);
                res.redirect("/register")
            } else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets")
                })
            }
            // Value 'result' is set to false. The user could not be authenticated since the user is not active
        });
    });

app.route("/submit")
    .get((req, res) => {
        if (req.isAuthenticated()) {
            res.render("submit")
        } else {
            res.redirect("/login")
        }
        
    })
    .post((req, res) => {
        const secret = req.body.secret;
        // console.log(req.user)
        req.user.secret = secret;
        req.user.save((err) => {
            if (err) {
                console.log(err)
            } else {
                res.redirect("/secrets")
            }
        })
    })
    
app.listen(3000, () => {
    console.log('Server started on port 3000')
})