import koa from 'koa';
import router from 'koa-router';
import bodyParser from 'koa-body';
import bcrypt from 'bcryptjs';
import dbConnect from '../db/dbConnect';
import User from '../db/models/user';
import jwtUtils from '../utils/jwt.utils';

require('dotenv').config();
const PORT = process.env.PORT || 4000;

dbConnect();

const app = new koa();
const _ = router();

//Set up body parsing middleware
app.use(bodyParser({
  multipart: true,
  urlencoded: true
}));

//Error handling middleware
app.use(async function(ctx, next) {
  try {
     await next();
  } catch (err) {
     ctx.status = err.status || 500;
     ctx.body = err.message;
     ctx.app.emit('error', err, ctx);
  }
});

_.get('/users', getUsers);
_.get('/user/:id', getUserById);
_.post('/user', addUser);
_.put('/user/:id', updateUser);
_.delete('/user/:id', deleteUser);
_.post('/login', login);
_.get('/me', getCurrentUser);

async function getUsers(ctx){
  try{
    const users = await User.find({});
    ctx.body = users;
  }
  catch(err){
    ctx.throw(404, JSON.stringify({error: err.message}))
  }
}

async function getUserById(ctx){
  try {
    const user = await User.findById(ctx.params.id);
    if(!user){
      ctx.throw(404, JSON.stringify('User Not Found'))
    }
    ctx.body=user;
  }
  catch(err){
    ctx.throw(404, JSON.stringify({error: err.message}))
  }
}

async function addUser(ctx){  
  const { email, password, firstName, lastName } = ctx.request.body
  if(!email || !password || !firstName || !lastName ){
    ctx.throw(400, JSON.stringify({error:'missing parameters'}))
  }
  const findUser = await User.find({email})
  if (findUser.length){
    ctx.throw(404, JSON.stringify({error:'User already exist'}))
  }
  try {
    const passwordHash = bcrypt.hashSync(ctx.request.body.password, 10);
    const user = new User({ ...ctx.request.body , password:passwordHash});
    const rep = await user.save();
    ctx.body = rep; 
  }
  catch(err){
    ctx.throw(404, JSON.stringify({error: err.message}));
  }
}

async function updateUser(ctx){
  const user = await User.findById(ctx.params.id);
  if(!user){
    ctx.throw(404, JSON.stringify({error: 'User Not Found'}))
  }
  try {
    const newUser = await User.findOneAndUpdate({ _id: ctx.params.id },{ $set: ctx.request.body},{new:true});
    ctx.body = newUser;
  }
  catch(err){
    ctx.throw(404, JSON.stringify({error: err.message}));
  }
}

async function deleteUser(ctx){
  const user = await User.findById(ctx.params.id);
  if(!user){
    ctx.throw(404, JSON.stringify({error: 'User Not Found'}));
  }
  try{
    ctx.body = await User.findOneAndRemove({ _id: ctx.params.id });
  }
  catch(err){
    ctx.throw(404, JSON.stringify({error: err.message}));
  }
}

async function login(ctx){
  const { email, password } = ctx.request.body
  if(!email || !password ){
    ctx.throw(400, JSON.stringify({error:'missing parameters'}))
  }
  try{
    const user = await User.findOne({email})
    if (!user) {
      ctx.throw(400,'wrong email');
    }
    if (!bcrypt.compareSync(password, user.password)) {
      ctx.throw(400,'wrong password');
    }
    const token = jwtUtils.generateTokenForUser(user)
    ctx.body = {
      token,
      user
    }
  }
  catch(err){
    ctx.throw(404, JSON.stringify({error: err.message}));
  }
}

async function getCurrentUser(ctx){
  try{
    const userId = jwtUtils.getUserId(ctx.header.authorization)
    if (userId < 0)
      ctx.throw(403,'wrong token')
    const user = await User.findById({_id: userId})
    if (!user){
      ctx.throw(404, JSON.stringify('User Not Found'))
    }
    ctx.body = user; 
  }
  catch(err){
    console.log(err)
    ctx.throw(404, JSON.stringify({error: err.message}))
  }
}

app.use(_.routes()); 

app.listen(PORT, () => {
  console.log(`server is running on port ${PORT}`);}
);