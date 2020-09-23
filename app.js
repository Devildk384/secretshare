//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const jwt = require('jsonwebtoken');
const nodemailer = require("nodemailer");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('Passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const bcrypt = require("bcrypt");
const saltRounds = 10;



const app = express();



app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended:true
}));

app.use(session({
  secret: "Im the best.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {userNewUrlParser: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
   email:String,
   password: String,
   googleId: String,
   facebookId: String,
   secret: String,
   resetLink:{data: String, default: ''}

});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);



passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/post",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID2,
    clientSecret: process.env.CLIENT_SECRET2,
    callbackURL: "http://localhost:3000/auth/facebook/post",

  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] }));

  app.get('/auth/google/post',
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {

    res.redirect("/secrets");
  });

  app.get('/auth/facebook',
  passport.authenticate('facebook',{ scope: ["profile"] } ));

app.get('/auth/facebook/post',
  passport.authenticate('facebook', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/reset", function(req, res){
  res.render("reset");
});

app.get("/register", function(req, res){
  res.render("register");
});



app.get("/secrets", function(req, res){
    User.find({"secret": {$ne:null}}, function(err, foundUsers){
     if (err) {
       console.log(err);
     } else{
       if (foundUsers) {
         res.render("secrets", {userWithSecrets: foundUsers});

       }
     }
   });
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  }else{
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
  const submitSecret = req.body.secret;

 console.log(req.user.id);

 User.findById(req.user.id, function(err, foundUser){
   if (err) {
     console.log(err);
   }else{
     if (foundUser) {
       foundUser.secret = submitSecret;
       foundUser.save(function(){
         res.redirect("/secrets");
       });

     }
   }
 });
});

app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res) {
     const newUser = new User({
        email:req.body.email,
        password:req.body.password
      });

     User.findOne({email:req.body.email}).exec((err, user) => {
    if(user){
           return res.status(400).json({error: "user with this email already exist."});
    }
    const token = jwt.sign({ email:req.body.email,password:req.body.password}, process.env.JWT_ACC_ACTIVATE,{expiresIn: '20m'});

    const smtpTransport = nodemailer.createTransport({
     service:'Gmail',
     auth:{
     user:'deepeshkumar384@gmail.com',
     pass:'Deepesh@123'

  }
});
  const mailOptions = {
    from: 'deepeshkumar384@gmail.com',
    to:req.body.email,
    subject: 'Activate Account',
     html: `
        <h2>Please click on the given link to activate your account</h2>
        <p>${process.env.CLIENT_URL}/${token}</p>`
  };
  smtpTransport.sendMail(mailOptions, function(error,user){
    if(error){
        console.log(err);
   } else
     {

       res.render("home");
     }

 });
});

 });

// verification link activate..

 app.get("/:token", function(req, res) {

const token = req.params;
console.log(req.params);
if(token) {
  jwt.verify(req.params.token, process.env.JWT_ACC_ACTIVATE, function(err, decodeToken){
    if(err){
      return res.status(400).json({error: 'Incorrect or Expired link.'})
    }

    const  {email,password}= decodeToken;

    User.findOne({email:req.body.email}).exec((err, user) => {
      if(user){
        return res.status(400).json({error: "user with this email already exist."});

      }else {

       bcrypt.hash(password, saltRounds, function(err, hash) {
         const newUser = new User({
           email:email,
           password:hash
         });


         newUser.save(function(err){
           if(err){

             console.log(err);
           }
           else{
             res.render("home");
           }
         });
      });

    }
    });

  })

}else{
  return res.json({error: 'Something went wrong!!!'})
}

});


// for reset Password

app.post("/reset", function(req, res) {


  const email = req.body.email;

  User.findOne({email:req.body.email}, (err, user) => {
    if(err || !user){
      return res.status(400).json({error: "user with this email does not exist."});

    }


    const token = jwt.sign({_id: user._id}, process.env.RESET_PASSWORD_KEY,{expiresIn: '20m'});
    console.log(token);
    console.log(user._id);



  const smtpTransport = nodemailer.createTransport({
   service:'Gmail',
   auth:{
     user:'deepeshkumar384@gmail.com',
     pass:'Deepesh@123'

  }
});
const mailOptions = {
  from: 'deepeshkumar384@gmail.com',
  to: user.email,
  subject: 'Reset password ',
   html:

      `
      <h2>Please click on the given link to reset the password</h2>
      <p>${process.env.CLIENT_URL}/update/${token}</p>`

};

return user.updateOne({resetLink: token}, function(err, success){
  if(err){
    return res.status(400).json({error: "reset password link error"});

  }else{
    smtpTransport.sendMail(mailOptions, function(error, body){
      if(error){

     } else{
       res.render("home");
     }

   });
  }
})
  })
})



// to update
app.get("/update/:token", function(req, res) {

const token= req.params;
console.log();
if(token) {
 jwt.verify(req.params.token, process.env.RESET_PASSWORD_KEY, function(err, decodeToken){
   if(err){
     return res.status(400).json({error: 'Incorrect or Expired link.'});

   }
   res.render('update');

 })

}else{
 return res.json({error: 'Something went wrong!!!'})
}

});


app.post('/update/:token', function(req, res){
const password = req.body.password;
 bcrypt.hash(password, saltRounds, function(err, hash) {
   const newUser = new User({
     password :hash
   });
   return User.updateOne({password: hash}, function(err, success){
     if(err){
       return res.status(400).json({error: "reset password link error"});

     }else{

       res.render('secrets');
     }



})
})



});



// for login

app.post("/login", function(req, res){

const email = req.body.email;
const password = req.body.password;

User.findOne({email: email}, function(err, foundUser){
  if(err){
    console.log(err);
  }else{
    if(foundUser){
      bcrypt.compare(password, foundUser.password, function(err, result){
        if( result === true){
          res.render('submit');
        }
      });
    }
  }
});

});




app.listen(3000, function(){
  console.log("server started on port 3000.");
});
