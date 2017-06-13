import { Router, Request, Response, NextFunction } from 'express';
import { Result } from 'express-validator';
import { default as User, UserModel } from '../models/user.model';
import * as passport from 'passport';
import * as passportLocal from 'passport-local';

exports.getHome = (req: Request, res: Response) => {
  let options: any = {};
  options.title = 'Home';

  res.render('info/home', options);
};
