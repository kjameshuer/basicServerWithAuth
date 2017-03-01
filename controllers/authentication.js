const jwt = require('jwt-simple');
const User = require('../models/user');
const config = require('../config');

function tokenForUser(user){
    const timestamp = new Date().getTime();
    return jwt.encode({ sub: user.id, iat:timestamp },config.secret);
}


exports.signin = function(req,res,next){
    //user authed, give token

    res.send({token:tokenForUser(req.user)});    

}

exports.signup = function(req,res,next){
   
    const email = req.body.email;
    const password = req.body.password;

    //if email or password are not sent
    if (!email || !password){
        return res.status(422).send({error:'You must provide email and password'})
    }

    //check if user exists
    User.findOne({email:email}, function(err, existingUser){
        //if search fails
        if (err) {return next(err)};

        //if user exists
        if (existingUser){
            return res.status(422).send({error: 'Email already exists'});
        }

        //if new user
        const user = new User({
            email:email,
            password: password
        });
            //save user to database
            user.save(function(err){
                //if save failed
                if (err) {return next(err);}
                //if save successful
                res.json({ token: tokenForUser(user)});
            });

    })


}