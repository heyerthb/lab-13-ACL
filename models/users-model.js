'use strict';

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const user = mongoose.Schema({
  username: {type:String, required: true, unique: true},
  password: {type: String, required: true},
  email: {type: String},
  role:{type:String, default: 'user', enum: ['admin', 'editor', 'user']},
});

const capabilities = {
  admin: ['create', 'read', 'update', 'delete'],
  editor: ['create', 'read'],
  user: ['read'],
};

user.pre('save', async function(){
  if(this.isModified('password')){
    this.password = await bcrypt.hash(this.password, 10);
  }
});

// user.authenticateToken = function (token){
//   let parsedToken = jwt.verify(token, process.env.SECRET);
//   return this.findOne({ _id: parsedToken.id});
// };

user.statics.authenticateBasic = function (auth){
  let query = {username: auth.username};
  return this.findOne(query)
    .then(user=>user && user.comparePassword(auth.password))
    .catch (error =>{throw error;
    });
};

user.methods.can = function (capability){
  return capabilities[this.role].includes(capability);
};

user.methods.generateToken = function (){
  let tokenData = {
    id: this._id,
    role: this.role,
  };
  return jwt.sign(tokenData, process.end.SECRET);
};

module.exports = mongoose.model('user', user);