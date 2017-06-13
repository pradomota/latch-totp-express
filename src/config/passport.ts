import { PassportStatic } from 'passport';
import * as passportLocal from 'passport-local';

import { default as User, UserModel } from '../models/user.model';
import { Request, Response, NextFunction } from 'express';

const LocalStrategy = passportLocal.Strategy;

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
          return done(null, false, { message: `Email ${email} not found.` });
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
}

export let isAuthenticated = (req: Request, res: Response, next: NextFunction) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

export let isNotLogged = (req: Request, res: Response, next: NextFunction) => {
  if (req.user) {
    return res.redirect('/');
  }
  return next();
};
