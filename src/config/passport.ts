import { PassportStatic } from 'passport';
import * as passportLocal from 'passport-local';

import { default as User, UserModel } from '../models/user.model';
import { Request, Response, NextFunction } from 'express';

const LocalStrategy = passportLocal.Strategy;
const CustomStrategy = require('passport-custom').Strategy;

export function setup(passport: PassportStatic): void {

  passport.serializeUser<any, any>((user, done) => {
    done(null, user.id);
  });

  passport.deserializeUser((id, done) => {
    User.findById(id, (err: Error, user: UserModel) => {
      done(err, user);
    });
  });

  passport.use('local-login', new LocalStrategy({
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true // allows us to pass back the entire request to the callback
    },
    function (req: Request, email: string, password: string, done) {
      User.findOne({ email: email.toLowerCase() }, (err, user: any) => {
        if (err) { return done(err); }
        if (!user) {
          return done(null, false, { message: `Invalid email or password.` });
        }
        user.checkPassword(password, (err: Error, isMatch: boolean) => {
          if (err) { return done(err); }
          if (isMatch) {
            return done(null, user);
          }
          return done(null, false, { message: 'Invalid email or password.' });
        });
      });
    })
  );

  passport.use('local-totp', new CustomStrategy(
    function(req: Request, done: any) {
      if (req.user && req.user.checkTOTP(req.body.code)) {
        done(null, req.user);
      } else {
        done(null, null, { message: 'Invalid code'});
      }
    }
  ));
}

export let isAuthenticated = (req: Request, res: Response, next: NextFunction) => {
  if (req.isAuthenticated()) {
    if (!req.user.totp.active || req.session.twoFactor) {
      return next();
    } else {
      return res.redirect('/two-factor');
    }
  }
  return res.redirect('/login');
};

export let isTwoFactorNeeded = (req: Request, res: Response, next: NextFunction) => {
  if (req.isAuthenticated()) {
      return next();
  }
  return res.redirect('/login');
};

export let isNotLogged = (req: Request, res: Response, next: NextFunction) => {
  if (req.user) {
    return res.redirect('/');
  }
  return next();
};
