if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config()
}

const express = require('express')
const app = express()
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const methodOverride = require('method-override')

const users = [] // Liste des utilisateurs, normalement ca vient de la db

const initializePassport = require('./passport-config')
initializePassport(
  passport,
  email => users.find(user => user.email === email), // Retourne l'utilisateur qui correspond à l'email
  id => users.find(user => user.id === id) // Retourne l'id qui correspond à l'utilisateur
)

app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())
app.use(methodOverride('_method'))

app.get('/', checkAuthenticated, (req, res) => {
  res.render('index.ejs', { name: req.user.name })
})

app.get('/login', checkNotAuthenticated, (req, res) => {
  res.render('login.ejs')
})

app.post('/login', checkNotAuthenticated, passport.authenticate('local', { // 'local' défini sa stratégie d'authentification
  successRedirect: '/',
  failureRedirect: '/login',
  failureFlash: true
}))

app.get('/register', checkNotAuthenticated, (req, res) => {
  res.render('register.ejs')
})

app.post('/register', checkNotAuthenticated, async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10) // bcrypt hash le mot de passe de l'utilisateur enregistré
    users.push({ // On ajoute le nouvel utilisateur au tableau 'users'
      id: Date.now().toString(), // Normalement, on devrait utiliser la clé primaire recupérée de la db entant que valeur
      name: req.body.name,
      email: req.body.email,
      password: hashedPassword
    })
    res.redirect('/login')
  } catch {
    res.redirect('/register')
  }
})

// Déconnexion
app.delete('/logout', (req, res) => {
  req.logOut() // 'logOut()' est une méthode de Passport.js qui permet de se déconnecter de la session
  res.redirect('/login')
})

// Vérifie que l'utilisateur est bien connecté pour executer tel ou tel middleware
// L'idéal serait d'implémenter cette fonction dans un fichier middleware dédié
function checkAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { // 'isAuthenticated()' est une méthode de Passport.js qui retourne 'true' si l'utilisateur est authentifié
    return next() 
  }

  res.redirect('/login')
}

// Vérifie que l'utilisateur n'est PAS connecté pour executer tel ou tel middleware
// L'idéal serait d'implémenter cette fonction dans un fichier middleware dédié
function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect('/')
  }
  next()
}

app.listen(3000)
