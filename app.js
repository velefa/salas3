var express = require('express');
var mysql = require('mysql');
var path = require('path');
var bodyParser = require('body-parser');
var bcrypt = require('bcrypt');
var cookieParser = require('cookie-parser');
var session = require('express-session');
var {body, validationResult} = require('express-validator');
require('dotenv').config()

var app = express()

app.set('view engine', 'ejs')
app.use('/public', express.static('public'))
app.use(bodyParser.urlencoded({extended: false}))
app.use(cookieParser())
app.use(session({
    secret: "Mysecretkey123",
    cookie: {maxAge: 30000},
    resave: false,
    saveUninitialized: false
}))

var conn = mysql.createConnection({
    host: 'localhost',
    user: process.env.USER,
    password: process.env.PASSWORD,
    database: 'nodeform'
})

conn.connect((err) => {
    if (err) throw err;
    console.log('Connected to the db successfully')
})

let registerErrors = []
let loginErrors = ''

app.get('/', (req, res) => {
    if (req.session.isAuth) {
        let current_user = req.cookies.current_user
        res.render('index', {username: current_user.username})
    }
    else{
        res.redirect('login')
    }
})

app.get('/register', (req, res) => {
    res.render('register', {message: registerErrors})
})

app.post('/register', 
body('username').trim().escape().isAlpha().withMessage('Username should be letters only').isLength({min: 4, max: 15}).withMessage('Username should be between 4 and 15 chars'),
body('email').trim().escape().isEmail().withMessage('Invalid email'),
body('age').trim().escape().isInt({min: 18, max: 50}).withMessage('Age should be between 18 and 50'),
body('password').trim().escape().isLength({min: 8}).withMessage('Password should be min 8 chars').matches('[0-9]').withMessage('Password must contain a number').matches('[A-Z]').withMessage('Password must contain an uppercase letter'),
body('confirmPassword').trim().escape().custom((value, {req}) => {
    if(value === req.body.password) return true
    else return false
}).withMessage('Passwords do not match'),
(req, res) => {
    var errors = validationResult(req);
    if (!errors.isEmpty()) {
        res.render('register', {message: errors.array()})
    }
    else {
        query1 = `SELECT count(*) as total from form where username = ?`
        conn.query(query1, [req.body.username], (err, result) => {
            if (result[0].total > 0){
                message = [{'msg': 'Username already exists'}]
                res.render('register', {message: message})
            }
            else {
                bcrypt.hash(req.body.password, 12).then(function(hashpass){
                    query2 = `INSERT INTO form VALUES (?, ?, ?, ?)`
                    conn.query(query2, [req.body.username, req.body.email, req.body.age, hashpass])
                    res.redirect('login', {message: loginErrors})
                })
            }
        })
    }
})

app.get('/login', (req, res) => {
    res.render('login', {message: loginErrors})
})

app.post('/login', (req, res) => {
    let {username, password} = req.body;
    passwordquery = `SELECT password from form where username = ?`
    counter = `SELECT count(*) as total from form where username = ?`
    conn.query(counter, [username], (err, result) => {
        if (result[0].total > 0){
            conn.query(passwordquery, [username], (err, result) => {
                let passwordDb = result[0].password;
                bcrypt.compare(password, passwordDb).then(function(result){
                    if (result){
                        req.session.isAuth = true
                        res.cookie('current_user', {username: username}, {maxAge: 30000})
                        setTimeout(() => {
                            console.log('Running')
                            res.redirect('/')

                        }, 3000)
                    }
                    else {
                        res.render('login', {message: 'Credentials are incorrect'})
                    }
                })
            })
        }
        else res.render('login', {message: 'Credentials are incorrect'})
    })
})

app.post('/logout', (req, res) => {
    req.session.isAuth = false
    res.clearCookie('connect.sid')
    res.clearCookie('current_user')
    req.session.destroy(function (err) {
      res.redirect('/');
    });
})


app.listen(3000);