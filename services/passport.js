const passport = require('passport');
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

//create local strategy
const localOptions = {
    usernameField: 'email'
}
const localLogin = new LocalStrategy(localOptions,function (email,password,done){
    //verify user/pass, call done with user if valid

    User.findOne({email:email},function(err,user){
        //if search error
        if (err) {return done(err);}

        if (!user) {return done(null,false);}

        //if supplied pass is equal to user pass
        user.comparePassword(password,function(err,isMatch){
            if (err) { return done(err)}

            if (!isMatch) {return done(null, false)}

            return done(null,user);
        })
    })

})

//setup options for jwt strategy
const jwtOptions ={
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey:config.secret
};

//create jwt strategy

const jwtLogin = new JwtStrategy(jwtOptions,function(payload, done){
    //see if the user ID in the payload exists in our database
    //if it does, call 'done with that user
    // otherwise, call done without a user object


    User.findById(payload.sub,function(err,user){
        //if request fails
        if (err) {return done(err,false);}

        if (user) {
            //user found
            done(null,user);
        }else{
            //user not found
            done(null,false);
        }

    });

});
//tell passport to use this strategy

passport.use(jwtLogin);
passport.use(localLogin);