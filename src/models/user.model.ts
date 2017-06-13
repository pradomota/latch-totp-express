import * as bcrypt from 'bcrypt';
import * as crypto from 'crypto';
import * as mongoose from 'mongoose';

export type UserModel = mongoose.Document & {
  email: string,
  password: string,
  name: string,

  checkPassword: (password: string, cb: (err: any, isMatch: any) => {}) => void
};

const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  name: String
}, { timestamps: true });

userSchema.pre('save', function save(next) {
  const user = this;
  if (!user.isModified('password')) {
    return next();
  }
  bcrypt.genSalt(10, (err: Error, salt) => {
    if (err) { return next(err); }
    bcrypt.hash(user.password, salt, (err: mongoose.Error, hash: string) => {
      if (err) { return next(err); }
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.checkPassword = function(password: string, cb: (err: Error, isMatch: boolean) => {}) {
  bcrypt.compare(password, this.password, (err: mongoose.Error , isMatch: boolean) => {
    cb(err, isMatch);
  });
};

const User = mongoose.model('User', userSchema);
export default User;
