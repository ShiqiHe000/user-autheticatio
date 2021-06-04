const bcrypt = require('bcrypt');
const LocalStrategy = require('passport-local').Strategy;

function initializePassport(passport, getUserByEmail, getUserById) {

    const authenticateUser = async (email, password, done) => {
        const user = getUserByEmail(email);
        if(user == null) {
            return done(null, false, {message: "No such user with this email."}); 
        }

        try {
            const result = await bcrypt.compare(password, user.password);

            if(!result) {
                return done(null, false, {message: 'Incorrect password.'});
            }

            return done(null, user);
        } catch (err) {
            console.log(err);
            done(err);
        }
    }

    passport.use(new LocalStrategy(
        {
            usernameField: 'email', 
            passwordField: 'password'
        }, 
        authenticateUser
    ))

    passport.serializeUser((user, done) => {
        return done(null, user.id);
    })

    passport.deserializeUser((id, done) => {
        const user = getUserById(id);
        if(user != null) {
            done(null, user);
        } else {
            done(null, false, {message: "No such user."});
        }
    })
}

module.exports = initializePassport;