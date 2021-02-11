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
  if(req.headers.auth!==undefined){
      jwt.verify(req.headers.auth, process.env.TOKEN_PASS, (err, decoded) => {
          if (err) throw (res.status(404).json({
              message:'session ended',icon:'error'
          }))
          console.log(decoded)
      })
      next()
      }
  else{
      res.status(404).json({
          message:"token not authorized",icon:'warning'
      })
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
                html: `<b>Click on the link to verify your email <a href="/String"><button type='button'>Click here</button></a></b>`,
            });

        await db.collection("user").insertOne(req.body);
        await db.collection("user").updateOne({"email": req.body.email},
        {$set: {verifystring: verifyString}})
        res.status(200).json({ message: "Check your mail for activation link" ,icon :'success' });
        clientInfo.close();
      }
    } catch (error) {
      console.log(error);
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
                res.send({message:'Your account is activated ,click below to Login',url:"#"})
                clientInfo.close()
        } else {
            res.send({message:"Link has expired"})
            clientInfo.close()
        }
    } catch (error) {
        console.log(error)
    }
})
  
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
      console.log(error);
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
          html: `<b>Click below to reset your password</b><br> <a href='/ResetPassword/${random}'>Reset</a>`
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
      console.log(err);
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
    console.log(err);
  }
  })

  app.get('/dashboard' ,[auth] ,async (req,res) => {
    try {
        let clientInfo = await mongoClient.connect(dbURL);
        let db = clientInfo.db("crm");
          var [service, leads, contacts] = await  Promise.all([db.collection("service_request").find().toArray() ,
                                                              db.collection("leads").find().toArray() , 
                                                              await db.collection("contacts").find().toArray() ])
        console.log(service.length ,leads.length , contacts.length)
        res.json({message : 'success' , service , leads , contacts })
    }
    catch (err) {
      console.log(err);
    }
})

app.post('/contact' , [auth], async (req,res) => {
  const emailData=localStorage.getItem('userdata').email
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({email : emailData })
      if(data !== null ){
          if(data.permission !== 'edit'){
              res.json({ message: "You do not have permission to add or edit" });
          }else if(data.permission === "edit" ) {
              var contacts = await db.collection("contacts").insertOne({ ...req.body })
              res.json({message : "success" , contacts : contacts })
          }
      }
  } catch (err) {
      console.log(err);
  }
})

app.get('/contact' ,[auth], async (req,res) => {
  const emailData=localStorage.getItem('userdata').email
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({email : emailData })
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
      console.log(err);
  }
})

app.put('/leads' , [auth] , async (req, res) => {
  const emailData=localStorage.getItem('userdata').email
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({email : emailData })
      if(data !== null ){
          if(data.permission !== "edit"){
              res.json({ message: "You do not have permission to add or edit" });
              await client.close()
          }else if(data.permission === "edit" ) {
              var contactmatch = await db.collection("contacts").findOne({email : req.body.email })
              if(contactmatch === null ){
                  res.status(404).json({ message: "Contact not found in database. Create a contact for the lead" });
                  await client.close()
              }
              var leads = await db.collection("leads").updateOne( {_id : mongodb.ObjectID(req.body._id)} ,
              {$set : {status : req.body.status , description : req.body.description , email : req.body.email , lastEditedAt : new Date() } } )
              res.json({message : "success" , leads : leads })
              await client.close()
                }
      }
      else{
          res.status(404).json({ message: "failed" });
          await client.close()
      }
  } catch (err) {
      console.log(err);
  }

})

app.post('/leads' ,[auth], async (req,res) => {
  const emailData=localStorage.getItem('userdata').email
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({email : emailData })
      if(data !== null ){
          if(data.permission !== "edit"){
              res.json({ message: "You do not have permission to add or edit" });
              await client.close()
          }else if(data.permission === "edit" ) {
              var contactmatch = await db.collection("contacts").findOne({email : req.body.email })
              if(contactmatch === null ){
                  res.status(404).json({ message: "Contact not found in database. Create a contact for the lead" });
                  await client.close()
              }
              req.body.createdBy = {name : data.name , email : data.email , access : data.access }
              req.body.createdAt = new Date()
              var leads = await db.collection("leads").insertOne({ ...req.body })
              res.json({message : "success" , leads : leads })
              await client.close()
          }
      }
      else{
          res.status(404).json({ message: "failed" });
          await client.close()
              }
  } catch (err) {
      console.log(err);
  }
})

app.get('/leads' ,[auth], async (req,res) => {
  const emailData=localStorage.getItem('userdata').email
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({email : emailData })
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
      console.log(err);
  }
})

app.put('/service' , [auth] , async (req, res) => {
  const emailData=localStorage.getItem('userdata').email
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({email : emailData })
      if(data !== null ){
          if(data.permission !== "edit"){
              res.json({ message: "You do not have permission to add or edit" });
              await client.close()
          }else if(data.permission === "edit" ) {
              var contactmatch = await db.collection("contacts").findOne({email : req.body.email })
              if(contactmatch === null ){
                  res.status(404).json({ message: "Contact not found in database. Create a contact for the lead" });
                  await client.close()
              }
              var service = await db.collection("service_request").updateOne( {_id : mongodb.ObjectID(req.body._id)} , {$set : {status : req.body.status , description : req.body.description , email : req.body.email , lastEditedAt : new Date() } } )
              res.json({message : "success" , service : service })
              await client.close()
          }
      }
      else{
          res.status(404).json({ message: "failed" });
          await client.close()
      }
  } catch (err) {
      console.log(err);
  }

})

app.get('/service' ,[auth], async (req,res) => {
  const emailData=localStorage.getItem('userdata').email
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({email : emailData })
      if(data !== null ){
          if(data.permission === 'none'){
              res.json({ message: "You do not have permission to view" });
          }else{
              const db = client.db("crm");
              var service = await db.collection("service_request").find().toArray()
              res.json({message : "success" , service : service })
          }
      }
      else{
          res.status(404).json({ message: "failed" });
      }
  } catch (err) {
      console.log(err);
  }
})

app.post('/service' ,[auth], async (req,res) => {
  const emailData=localStorage.getItem('userdata').email
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({email : emailData })
      if(data !== null ){
          if(data.permission !== "edit"){
              res.json({ message: "You do not have permission to add or edit" });
              await client.close()
          }else if(data.permission === "edit" ) {
              var contactmatch = await db.collection("contacts").findOne({email : req.body.email })
              
              if(contactmatchl ){
                  res.status(404).json({ message: "Contact not found in database. Create a contact for the service request" });
                  await client.close()
              }
              req.body.createdBy = {nae : data.name , email : data.email , access : data.access }
              req.body.createdAt = new Date()
              var service = await db.collection("service_request").insertOne({ ...req.body })
              res.json({message : "success" , service : service })
              await client.close()
          }
      }
      else{
          res.status(404).json({ message: "failed" });
          await client.close()
      }
  } catch (err) {
      console.log(err);
  }
})

app.post('/access' , [auth] , async (req,res) => { 
  const emailData=localStorage.getItem('userdata').email
  try {
    let clientInfo = await mongoClient.connect(dbURL, {useNewUrlParser: true , useUnifiedTopology: true } );
    let db = clientInfo.db("crm");
      var data = await db.collection("user").findOne({email : emailData })
      if(data.access === 'manager' || data.access === 'admin' && data.permission === "edit"  ) {
        var users = await db.collection("user").updateOne({_id : objectId(req.body._id) } , {$set : {permission : req.body.permission} })
        res.json({message : "success" , users : users })
      }
      else{
          res.status(404).json({message : 'You do not have permission to edit'})
      }
  } catch (err) {
      console.log(err)
  }
})

app.get('/access' , [auth] , async (req,res) => { 
  const emailData=localStorage.getItem('userdata').email
  try {
    let clientInfo = await mongoClient.connect(dbURL);
    let db = clientInfo.db("crm");
    var data = await db.collection("user").findOne({email : emailData })
      if( ( data.access === 'manager' || data.access === 'admin' ) && ( data.permission === 'view' || data.permission === "edit" ) ) {
        var users = await db.collection("user").find({access : {$not : /^admin/ } } , {password : 0 } ).toArray()
        users = users.filter(user => user.email !== data.email )
        res.json({message : "success" , users : users })
        await client.close()
      }
      else{
          res.status(404).json({message : 'You do not have permission to view'})
          await client.close()
      }
  } catch (err) {
    console.log(err)      
  }
})


app.listen(port, () => console.log("your app runs with port:",port));