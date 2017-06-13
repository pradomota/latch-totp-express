import * as express from 'express';
import * as path from 'path';
import * as logger from 'morgan';
import * as bodyParser from 'body-parser';
import * as cookieParser from 'cookie-parser';
import * as session from 'express-session';
import * as dotenv from 'dotenv';
import * as mongo from 'connect-mongo';
import * as mongoose from 'mongoose';
import * as passport from 'passport';
import * as expressValidator from 'express-validator';
import * as passportConfig from './config/passport';

var routes = require('./routes/app.routes');
var lessMiddleware = require('less-middleware');

dotenv.config();
const MongoStore = mongo(session);

export class Server {

  public app: express.Application;

  constructor() {
    this.app = express();
    this.configure();
    this.routes();
    this.errors();
  }

  private configure(): void {

    mongoose.connect(process.env.MONGODB_URI);
    mongoose.connection.on('error', () => {
      console.log('MongoDB connection error. Please make sure MongoDB is running.');
      process.exit();
    });


    this.app.set('views', path.join(__dirname, 'views'));
    this.app.set('view engine', 'pug');

    this.app.use(logger('dev'));
    this.app.use(bodyParser.json());
    this.app.use(bodyParser.urlencoded({ extended: false }));
    this.app.use(expressValidator());
    this.app.use(cookieParser());
    this.app.use(session({
      resave: true,
      saveUninitialized: true,
      secret: process.env.COOKIE_SECRET || '',
      store: new MongoStore({
        url: process.env.MONGODB_URI || process.env.MONGOLAB_URI,
        autoReconnect: true
      })
    }));

    passportConfig.setup(passport);
    this.app.use(passport.initialize());
    this.app.use(passport.session());

    this.app.use(lessMiddleware(path.join(__dirname, 'public')));
    this.app.use(express.static(path.join(__dirname, 'public')));
  }

  private errors(): void {

    // catch 404 and forward to error handler
    this.app.use((req: express.Request, res: express.Response,
      next: express.NextFunction): void => {
        let err: any = new Error('Not Found');
        err.status = 404;
        next(err);
    });

    this.app.use((err: any, req: express.Request,
      res: express.Response, next: express.NextFunction): void => {
        // set locals, only providing error in development
        res.locals.message = err.message;
        res.locals.error = req.app.get('env') === 'development' ? err : {};

        res.status(err.status || 500);
        res.render('error');
    });
  }

  private routes(): void {
    this.app.use('/', routes);
  }
}

export default new Server().app;
