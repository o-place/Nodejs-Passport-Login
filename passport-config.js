const LocalStrategy = require('passport-local').Strategy
const bcrypt = require('bcrypt')

function initialize(passport, getUserByEmail, getUserById) {
  
  // Strategie d'authentification
  const authenticateUser = async (email, password, done) => {
    
    const user = getUserByEmail(email) // retourne l'utilisateur qui correspond à l'email
    if (user == null) {
      return done(null, false, { message: 'No user with that email' }) // Si il n'y a pas d'utilisateur qui correspond à l'email
    }
    
    try {
      if (await bcrypt.compare(password, user.password)) { // Bcrypt vérifie si le password est correct
        return done(null, user) // Si c'est le cas, retourne true
      } else {
        return done(null, false, { message: 'Password incorrect' }) // Sinon, retourne false
      }
    } catch (err) {
      return done(err) // Si une erreur est générée, on retourne l'erreur
    }
  }

  // usernameField: nom de la key dans req.body, par défaut la valeur est 'username', il faut taper le bon nom de champs pour que passport le trouve (dans ce cas: req.body.email)
  passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))
  
  // serializeUser() sets an id (the user email in this case) as the cookie in the user's browser, Passport takes that user id and stores it internally on req.session
  passport.serializeUser((user, done) => done(null, user.id))

  // deserializeUser() function uses the id from the session (user email in this case) to look up the user in the database and retrieve the user object with data, and attach it to req.user
  passport.deserializeUser((id, done) => done(null, getUserById(id))
}

module.exports = initialize
