const User = require('../models/user');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cryptojs = require('crypto-js');
const mongoSanitize = require('express-mongo-sanitize');
//require('dotenv').config();

exports.signup = (req, res, next) => {
    const hashedEmail = cryptojs
        .HmacSHA512(req.body.email, 'RANDOM_KEY_SECRET')
        .toString(cryptojs.enc.Base64);
    console.log('hashedEmail=' + hashedEmail);
    bcrypt
        .hash(mongoSanitize(req.body.password), 10)
        .then(hash => {
            const user = new User({
                email: hashedEmail,
                password: hash,
            });
            user.save()
                .then(() => res.status(201).json({ message: 'Utilisateur créé !' }))
                .catch(error => res.status(400).json({ error }));
        })
        .catch(error => {
            console.log('signup - catch bcrypt=' + error);
            return res.status(500).json({ error });
        });
};

exports.login = (req, res, next) => {
    const hashedEmail = cryptojs
        .HmacSHA512(req.body.email, 'RANDOM_KEY_SECRET')
        .toString(cryptojs.enc.Base64);
    User.findOne({ email: hashedEmail })
        .then(user => {
            if (!user) {
                return res.status(401).json({ error: 'Utilisateur non trouvé !' });
            }
            bcrypt
                .compare(req.body.password, user.password)
                .then(valid => {
                    if (!valid) {
                        return res
                            .status(401)
                            .json({ error: 'Mot de passe incorrect !' });
                    }
                    res.status(200).json({
                        userId: user._id,
                        token: jwt.sign({ userId: user._id }, 'RANDOM_TOKEN_SECRET', {
                            expiresIn: '24h',
                        }),
                    });
                })
                .catch(error => {
                    console.log('login - catch bcrypt=' + error);
                    return res.status(500).json({ error });
                });
        })
        .catch(error => {
            console.log('login -catch global=' + error);
            res.status(500).json({ error });
        });
};
