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

  // usernameField: nom de l'user, par défaut la valeur est 'username'
  passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser))
  
  // permet d'enregistrer l'utilisateur dans la session, via l'id de l'utilisateur
  passport.serializeUser((user, done) => done(null, user.id))
  
  // permet de supprimer l'utilisateur de la session
  passport.deserializeUser((id, done) => done(null, getUserById(id))
}

module.exports = initialize
