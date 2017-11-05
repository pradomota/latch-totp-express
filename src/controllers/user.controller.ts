import { Router, Request, Response, NextFunction } from 'express';
import { Result } from 'express-validator';
import { default as User, UserModel } from '../models/user.model';
import * as passport from 'passport';
import * as passportLocal from 'passport-local';

exports.getLogin = (req: Request, res: Response) => {
  let options: any = {};
  options.title = 'Login';

  res.render('user/login', options);
};

exports.postLogin = (req: Request, res: Response, next: NextFunction) => {
  let options: any = {};
  options.title = 'Login';

  req.assert('email', 'Invalid email format').isEmail();
  req.assert('password', 'Password must not be empty').notEmpty();

  req.sanitize('email').trim();

  req.getValidationResult().then((result: Result) => {
    const user = new User({
      email: req.body.email
    });
    options.user = user;

    if (result.isEmpty()) {
      passport.authenticate('local-login', (err: Error, user: UserModel, info: any) => {
        if (err) { return next(err); }
        if (!user) {
          options.errors = { auth: { param: 'auth', msg: info.message}};
          res.render('user/login', options);
        }
        req.logIn(user, (err) => {
          if (err) { return next(err); }
          //req.flash("success", { msg: "Success! You are logged in." });
          res.redirect(req.session.returnTo || '/');
        });
      })(req, res, next);

    } else {
      options.errors = result.mapped();
      res.render('user/login', options);
    }
  });

};

exports.getTwoFactor = (req: Request, res: Response) => {
  let options: any = {};
  options.title = 'Two-Factor';

  res.render('user/two-factor', options);
};

exports.postTwoFactor = (req: Request, res: Response, next: NextFunction) => {
  let options: any = {};
  options.title = 'Two-Factor';

  req.assert('code', 'Code must not be empty').notEmpty();
  req.getValidationResult().then((result: Result) => {
    if (result.isEmpty()) {
      passport.authenticate('local-totp', (err: Error, user: UserModel, info: any) => {
        if (err) {
          next(err);
        } else if (!user) {
          options.errors = { code: { param: 'code', msg: info.message } };
          res.render('user/two-factor', options);
        } else {
          req.session.twoFactor = true;
          res.redirect(req.session.returnTo || '/');
        }
      })(req, res, next);
    } else {
      options.errors = result.mapped();
      res.render('user/two-factor', options);
    }
  });
};

exports.getSignup = (req: Request, res: Response) => {
  let options: any = {};
  options.title = 'Create Account';

  res.render('user/sign-up', options);
};

exports.postSignup = (req: Request, res: Response, next: NextFunction) => {
  var options: any = {};
  options.title = 'Create Account';

  req.assert('name', 'Name must not be empty').notEmpty();
  req.assert('email', 'Invalid email format').isEmail();
  req.assert('password', 'Password must be at least 8 characters long').len(<ExpressValidator.Options.MinMaxOptions>{ min: 8 });
  req.assert('confirmPassword', 'Passwords do not match').equals(req.body.password);

  req.sanitize('name').escape();
  req.sanitize('email').trim();

  req.getValidationResult().then((result: Result) => {

    const user = new User({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password
    });
    options.user = user;

    if (result.isEmpty()) {
      User.findOne({ email: req.body.email })
          .then((existingUser: UserModel) => {
            if (existingUser) {
              options.errors = { email: { param: 'email', msg: 'Account with that email address already exists' } };
              res.render('user/sign-up', options);
            } else {
              user.save()
                  .then(() => {
                    req.logIn(user, (err: Error) => {
                      if (err) { return next(err); }
                      res.redirect('/');
                    });
                  })
                  .catch((err: Error) => next(err));
            }
          })
          .catch((err: Error) => next(err));
    } else {
      options.errors = result.mapped();
      res.render('user/sign-up', options);
    }
  });
};

exports.getLogout = (req: Request, res: Response, next: NextFunction) => {
  req.logout();
  req.session.destroy(function (err: Error) {
    if (err) { return next(err); }
    res.redirect('/');
  });
};

exports.getProfile = (req: Request, res: Response) => {
  let options: any = {};
  options.title = 'Profile';
  options.user = req.user;

  res.render('user/profile', options);
};


exports.postConfigureTwoFactor = (req: Request, res: Response, next: NextFunction) => {
  let options: any = {};
  options.title = 'Profile';
  options.user = req.user;

  req.assert('password', 'Password must not be empty').notEmpty();
  req.getValidationResult().then((result: Result) => {
    if (result.isEmpty()) {
      options.user.checkPassword(req.body.password, (err: Error, isMatch: boolean) => {
        if (err) {
          next(err);
        } else if (!isMatch) {
          options.errors = { password: { param: 'password', msg: 'Wrong password'} };
          res.render('user/profile', options);
        } else  {
          let totpUri: string = options.user.configureTOTP();
          options.totpQR = `https://chart.googleapis.com/chart?chs=166x166&chld=L|0&cht=qr&chl=${encodeURIComponent(totpUri)}`;
          options.user.save()
            .then(() => {
              res.render('user/profile', options);
            })
            .catch((err: Error) => next(err));
        }
      });
    } else {
      options.errors = result.mapped();
      res.render('user/profile', options);
    }
  });
};

exports.postActivateTwoFactor = (req: Request, res: Response, next: NextFunction) => {
  let options: any = {};
  options.title = 'Profile';
  options.user = req.user;
  options.totpQR = req.body.totpQR;

  req.assert('code', 'Code must not be empty').notEmpty();
  req.getValidationResult().then((result: Result) => {
    if (result.isEmpty()) {
      passport.authenticate('local-totp', (err: Error, user: UserModel, info: any) => {
        if (err) {
          next(err);
        } else if (!user) {
          options.errors = { code: { param: 'code', msg: info.message } };
          res.render('user/profile', options);
        } else {
          req.session.twoFactor = true;
          options.user.totp.active = true;
          options.user.save()
            .then(() => {
              res.redirect('/profile');
            })
            .catch((err: Error) => next(err));
        }
      })(req, res, next);
    } else {
      options.errors = result.mapped();
      res.render('user/profile', options);
    }
  });
};


exports.postDisableTwoFactor = (req: Request, res: Response, next: NextFunction) => {
  let options: any = {};
  options.title = 'Profile';
  options.user = req.user;

  req.assert('password', 'Password must not be empty').notEmpty();
  req.getValidationResult().then((result: Result) => {
    if (result.isEmpty()) {
      options.user.checkPassword(req.body.password, (err: Error, isMatch: boolean) => {
        if (err) {
          next(err);
        } else if (!isMatch) {
          options.errors = { password: { param: 'password', msg: 'Wrong password' } };
          res.render('user/profile', options);
        } else {
          options.user.disableTOTP();
          options.user.save()
            .then(() => {
              res.redirect('/profile');
            })
            .catch((err: Error) => next(err));
        }
      });
    } else {
      options.errors = result.mapped();
      res.render('user/profile', options);
    }
  });
};