const express = require('express')
const bodyParser = require('body-parser')
require("dotenv").config();
const mongodb = require("mongodb");
const cors = require("cors");
const bcrypt = require("bcrypt");
var jwt = require('jsonwebtoken');
const app = express();
app.use(cors());
app.use(bodyParser.json());


const nodemailer = require("nodemailer")
const mongoClient = mongodb.MongoClient;
const objectId = mongodb.ObjectID


const dbURL = process.env.DB_URL ||"mongodb://127.0.0.1:27017";
const port = process.env.PORT || 4000

let auth = (req, res, next) => {
  try{
  if(req.headers.auth!==undefined){
      let jwttoken = jwt.verify(req.headers.auth, process.env.TOKEN_PASS)
      res.locals.userid = jwttoken.userid
      next()
      }
  else{
      res.status(404).json({message:"token not authorized"})
  }
}
  catch(err){
    console.error(err)
    res.status(404).json({message:"authorization failed"})
  }
}

app.post("/register", async (req, res) => {
    try {
      let clientInfo = await mongoClient.connect(dbURL);
      let db = clientInfo.db("crm");
      let result = await db
        .collection("user")
        .findOne({ email: req.body.email });
      if (result) {
        res.status(400).json({ message: "User already registered" ,icon :'warning'});
      } else {
        let salt = await bcrypt.genSalt(15);
        let hash = await bcrypt.hash(req.body.password, salt);
        req.body.password = hash;

        let verifyString = (Math.random() * 1e32).toString(36)
        let transporter = nodemailer.createTransport({
                host: "smtp.gmail.com",
                port: 587,
                secure: false, 
                auth: {
                  user: process.env.MAIL_USERNAME, 
                  pass: process.env.MAIL_PASSWORD, 
                },
            });

        let info = await transporter.sendMail({
                from: `Easy CRM <${process.env.MAIL_USERNAME}>`, 
                to: `${req.body.email}`, 
                subject: "Verification mail",
                text: "click to Verify your email and activate your account", 
                html: `<b>Click on the link to verify your email <a href="https://easy-crm.netlify.app/String/${verifyString}">https://easy-crm.netlify.app/String/${verifyString}</a></b>`,
            });

        await db.collection("user").insertOne(req.body);
        await db.collection("user").updateOne({"email": req.body.email},
        {$set: {verifystring: verifyString}})
        res.status(200).json({ message: "Check your mail for activation link" ,icon :'success' });
        clientInfo.close();
      }
    } catch (error) {
      console.error(error);
    }
  })

  app.get('/confirm/:verifyString', async (req, res) => {
    try {
        let clientInfo = await mongoClient.connect(dbURL)
        let db = clientInfo.db("crm")
        let result = await db.collection("user").findOne({ verifystring: req.params.verifyString})
        if (result) {
                await db.collection("user").updateOne({
                    verifystring: req.params.verifyString
                }, {
                    $set: {
                        status: true,
                        verifystring: ''
                    }
                })
                res.send({message:'Your account is activated ,Go to Login'})
                res.redirect('/Login')
                clientInfo.close()
        } else {
            res.send({message:"Link has expired"})
            clientInfo.close()
        }
    } catch (error) {
        console.error(error)
    }
})
  app.get('/login' ,[auth] , (req,res)=>{
    try{
      if(res.locals.userid){
        res.json({message : true})
      }else{
        res.json({message : false})
      }
    }catch(err){
      console.error(err);
      res.status(400).json({messages:err})
    }
  } )
  app.post("/login", async (req, res) => {
    try {
      let clientInfo = await mongoClient.connect(dbURL);
      let db = clientInfo.db("crm");
      let result = await db
        .collection("user")
        .findOne({$and:[{ email: req.body.email },{status:true}]});
      if (result) {
        let isTrue = await bcrypt.compare(req.body.password, result.password);
        if (isTrue) {
          let token = jwt.sign({"userid":result._id,"username":result.username},process.env.TOKEN_PASS)
          res.status(200).json({ message: "Logged in successfully",result ,token,icon :'success'})
          clientInfo.close();
        } else {
          res.status(200).json({ message: "Incorrect Password" ,icon :'warning' });
        }
      } else {
        res.status(400).json({ message: "User not registered" ,icon :'warning' });
      }
    } catch (error) {
      console.error(error);
    }
  })

  app.post('/forgotpassword',async (req,res)=>{
    try {
      let clientInfo = await mongoClient.connect(dbURL);
      let db = clientInfo.db("crm");
      let result = await db.collection("user").findOne({ email: req.body.email })

      if (result) {
        let random=(Math.random()*1e32).toString(36)

        let transporter = nodemailer.createTransport({
          host: "smtp.gmail.com",
          port: 587,
          secure: false, 
          auth: {
            user: process.env.MAIL_USERNAME, 
            pass: process.env.MAIL_PASSWORD, 
          },
        })
        let info = await transporter.sendMail({
          from: `Easy CRM <${process.env.MAIL_USERNAME}>`, 
          to: `${req.body.email}`, 
          subject: "Password Reset", 
          text: "Reset your password", 
          html: `<b>Click below to reset your password</b><br> <a href='https://easy-crm.netlify.app/ResetPassword/${random}'>https://easy-crm.netlify.app/ResetPassword/${random}</a>`
        })
        await db.collection("user").updateOne({ email: req.body.email },{$set:{'randomstring':random}});
        res.status(200).json({message: `Thanks! Please check ${req.body.email} for a link to reset your password.`,icon:'success'});
        clientInfo.close()
      }
      else{
        res.status(400).json({message: "User doesn't exists",icon:'warning'});
      }
    }
    catch(err){
      console.error(err);
    }
  })

  app.post('/reset',async(req,res)=>{
    try {
      let clientInfo = await mongoClient.connect(dbURL);
      let db = clientInfo.db("crm");
      let result = await db.collection("user").findOne({randomstring : req.body.randomstring})
      if(result){
        let salt = await bcrypt.genSalt(15);
        let password = await bcrypt.hash(req.body.password, salt);
        await db.collection("user").updateOne({
        randomstring: req.body.randomstring}, {$set: {
                    randomstring: '',
                    password: password
                }})
        res.status(200).json({message: "Password Changed successfully" ,icon :'success'});
        clientInfo.close();
      }else{
        res.status(410).json({message: "some error in page" ,icon :'error'});
      }
  }
  catch(err){
    console.error(err);
  }
  })

  app.get('/dashboard' ,[auth] ,async (req,res) => {
    try {
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db("crm");
          var [service, leads, contacts] = await  Promise.all([db.collection("service_request").find().toArray() ,
                                                              db.collection("leads").find().toArray() , 
                                                              await db.collection("contacts").find().toArray() ])
        res.json({message : 'success' , service , leads , contacts })
    }
    catch (err) {
      console.error(err);
    }
})

app.post('/contact' , [auth], async (req,res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({_id : mongodb.ObjectID(res.locals.userid) })
      if(data !== null ){
          if(data.permission !== 'edit'){
              res.json({ message: "You do not have permission to add or edit" });
          }else if(data.permission === "edit" ) {
              var contacts = await db.collection("contacts").insertOne({ ...req.body })
              res.json({message : "success" , contacts : contacts })
          }
      }
  } catch (err) {
      console.error(err);
  }
})

app.put('/contact/:id' , [auth], async (req,res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({_id : mongodb.ObjectID(res.locals.userid) })
      if(data !== null ){
          if(data.permission !== 'edit'){
              res.json({ message: "You do not have permission to add or edit" });
              await clientInfo.close()
          }else if(data.permission === "edit" ) {
              var contacts = await db.collection("contacts").findOneAndDelete({_id:mongodb.ObjectID(req.params.id)})
              res.json({message : "success" , contacts : contacts })
          }
      }
  } catch (err) {
      console.error(err);
  }
})

app.get('/contact' ,[auth], async (req,res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({_id : mongodb.ObjectID(res.locals.userid) })
      if(data !== null ){
          if(data.permission === 'none'){
              res.json({ message: "You do not have permission to view" });
          }else{
            let db = clientInfo.db("crm");
            var contacts = await db.collection("contacts").find().toArray()
            res.json({message : "success" , contacts : contacts })
          }
      }
  } catch (err) {
      console.error(err);
  }
})

app.put('/leads' , [auth] , async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({_id : mongodb.ObjectID(res.locals.userid) })
      if(data !== null ){
          if(data.permission !== "edit"){
              res.json({ message: "You do not have permission to add or edit" });
              await clientInfo.close()
          }else if(data.permission === "edit" ) {
              var contactmatch = await db.collection("contacts").findOne({email : req.body.email })
              if(contactmatch === null ){
                  res.status(404).json({ message: "Contact not found in database. Create a contact for the lead" });
                  await clientInfo.close()
              }
              var leads = await db.collection("leads").updateOne( {_id : mongodb.ObjectID(req.body._id)} ,
              {$set : {status : req.body.status , description : req.body.description , email : req.body.email , lastEditedAt : new Date() } } )
              res.json({message : "success" , leads : leads })
              await clientInfo.close()
                }
      }
      else{
          res.status(404).json({ message: "failed" });
          await clientInfo.close()
      }
  } catch (err) {
      console.error(err);
  }

})

app.post('/leads' ,[auth], async (req,res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({_id : mongodb.ObjectID(res.locals.userid) })
      if(data !== null ){
          if(data.permission !== "edit"){
              res.json({ message: "You do not have permission to add or edit" });
              await clientInfo.close()
          }else if(data.permission === "edit" ) {
              var contactmatch = await db.collection("contacts").findOne({email : req.body.email })
              if(contactmatch === null ){
                  res.status(404).json({ message: "Contact not found in database. Create a contact for the lead" });
                  await clientInfo.close()
              }
              req.body.createdBy = {name : data.name , email : data.email , access : data.access }
              req.body.createdAt = new Date()
              var leads = await db.collection("leads").insertOne({ ...req.body })
              res.json({message : "success" , leads : leads })
              await clientInfo.close()
          }
      }
      else{
          res.status(404).json({ message: "failed" });
          await clientInfo.close()
              }
  } catch (err) {
      console.error(err);
  }
})

app.get('/leads' ,[auth], async (req,res) => {
  try {
      let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({_id : mongodb.ObjectID(res.locals.userid) })
      if(data !== null ){
          if(data.permission === 'none'){
              res.json({ message: "You do not have permission to view" });
          }else{
            let db = clientInfo.db("crm");
            var leads = await db.collection("leads").find().toArray()
              res.json({message : "success" , leads : leads })
          }
      }
      else{
          res.status(404).json({ message: "failed" });
      }
  } catch (err) {
      console.error(err);
  }
})

app.put('/service' , [auth] , async (req, res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({_id : mongodb.ObjectID(res.locals.userid) })
      if(data !== null ){
          if(data.permission !== "edit"){
              res.json({ message: "You do not have permission to add or edit" });
              await clientInfo.close()
          }else if(data.permission === "edit" ) {
              var contactmatch = await db.collection("contacts").findOne({email : req.body.email })
              if(contactmatch === null ){
                  res.status(404).json({ message: "Contact not found in database. Create a contact for the lead" });
                  await clientInfo.close()
              }
              var service = await db.collection("service_request").updateOne( {_id : mongodb.ObjectID(req.body._id)} , {$set : {status : req.body.status , description : req.body.description , email : req.body.email , lastEditedAt : new Date() } } )
              res.json({message : "success" , service : service })
              await clientInfo.close()
          }
      }
      else{
          res.status(404).json({ message: "failed" });
          await clientInfo.close()
      }
  } catch (err) {
      console.error(err);
  }

})

app.get('/service' ,[auth], async (req,res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({_id : mongodb.ObjectID(res.locals.userid) })
      if(data !== null ){
          if(data.permission === 'none'){
              res.json({ message: "You do not have permission to view" });
          }else{
              const db = clientInfo.db("crm");
              var service = await db.collection("service_request").find().toArray()
              res.json({message : "success" , service : service })
          }
      }
      else{
          res.status(404).json({ message: "failed" });
      }
  } catch (err) {
      console.error(err);
  }
})

app.post('/service' ,[auth], async (req,res) => {
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({_id : mongodb.ObjectID(res.locals.userid) })
      if(data !== null ){
          if(data.permission !== "edit"){
              res.json({ message: "You do not have permission to add or edit" });
              await clientInfo.close()
          }else if(data.permission === "edit" ) {
              var contactmatch = await db.collection("contacts").findOne({email : req.body.email })
              if(contactmatch===null){
                  res.status(404).json({ message: "Contact not found in database. Create a contact for the service request" });
                  await clientInfo.close()
              }
              req.body.createdBy = {name : data.name , email : data.email , access : data.access }
              req.body.createdAt = new Date()
              var service = await db.collection("service_request").insertOne({ ...req.body })
              res.json({message : "success" , service : service })
              await clientInfo.close()
          }
      }
      else{
          res.status(404).json({ message: "failed" });
          await clientInfo.close()
      }
  } catch (err) {
      console.error(err);
  }
})

app.post('/access' , [auth] , async (req,res) => { 
  try {
    let clientInfo = await mongoClient.connect(dbURL, {useNewUrlParser: true , useUnifiedTopology: true } );
    let db = clientInfo.db("crm");
      var data = await db.collection("user").findOne({_id : mongodb.ObjectID(res.locals.userid) })
      if(data.access === 'admin' && data.permission === "edit"  ) {
        var users = await db.collection("user").updateOne({_id : objectId(req.body._id) } , {$set : {permission : req.body.permission} })
        res.json({message : "success" , users : users })
      }
      else{
          res.status(404).json({message : 'You do not have permission to edit'})
      }
  } catch (err) {
      console.error(err)
  }
})

app.get('/access' , [auth] , async (req,res) => { 
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({_id : mongodb.ObjectID(res.locals.userid) })
      if( data.access === 'admin' && ( data.permission === 'view' || data.permission === "edit" ) ) {
        var users = await db.collection("user").find({access : {$not : /^admin/ } } , {password : 0 } ).toArray()
        users = users.filter(user => user.email !== data.email )
        res.json({message : "success" , users : users })
        await clientInfo.close()
      }
      else{
          res.status(404).json({message : 'You do not have permission to view'})
          await clientInfo.close()
      }
  } catch (err) {
    console.error(err)      
  }
})


app.listen(port, () => console.log("your app runs with port:",port));