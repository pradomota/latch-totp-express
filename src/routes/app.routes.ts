import { Router, Request, Response, NextFunction } from 'express';
import * as passportConfig from '../config/passport';

let users = require('../controllers/user.controller');
let info = require('../controllers/info.controller');

let router: Router = Router();

router.get('/login', passportConfig.isNotLogged, users.getLogin);
router.post('/login', passportConfig.isNotLogged, users.postLogin);
router.get('/two-factor', passportConfig.isTwoFactorNeeded, users.getTwoFactor);
router.post('/two-factor', passportConfig.isTwoFactorNeeded, users.postTwoFactor);
router.get('/sign-up', passportConfig.isNotLogged, users.getSignup);
router.post('/sign-up', passportConfig.isNotLogged, users.postSignup);
router.get('/logout', passportConfig.isAuthenticated, users.getLogout);

router.get('/profile', passportConfig.isAuthenticated, users.getProfile);
router.post('/profile/configure-two-factor', passportConfig.isAuthenticated, users.postConfigureTwoFactor);
router.post('/profile/activate-two-factor', passportConfig.isAuthenticated, users.postActivateTwoFactor);
router.post('/profile/disable-two-factor', passportConfig.isAuthenticated, users.postDisableTwoFactor);

router.get('/', passportConfig.isAuthenticated, info.getHome);

module.exports = router;
