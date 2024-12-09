const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const fs = require('fs');
const app = express();

app.use(bodyParser.json());

const PORT = 3000;
const SECRET_KEY = 'private6789';

const readUsers = () =>JSON.parse(fs.readFileSync('users.json','utf8'));
const writeUsers = (data) => fs.writeFileSync('users.json',JSON.stringify(data,null,2))

// Middleware 
const authenticateToken = (req,res,next)=> {
    const token = req.headers['authorization']?.split(' ')[1]
    if (!token) return res.status(401).json({ error: 'Authentication token is required' })
    jwt.verify(token, SECRET_KEY, (err,user) => {
        if (err) return res.status(403).json({error:'Invalid token'})
        req.user=user
        next()
    })
}


app.post('/register',async(req,res) =>{
    const {firstName,lastName,email,password,phone}=req.body

    if (!email || !password) 
        return res.status(400).json({error:'Email and password are required'})
    const users = readUsers()
    if (users.find((user) => user.email === email))
        return res.status(400).json({error:'User already exists'});

    // Encrypt password
    const hashedPassword=await bcrypt.hash(password,10)

    const newUser = {
        id: users.length + 1,
        firstName,
        lastName,
        email,
        password: hashedPassword,
        phone,
    }
    users.push(newUser)
    writeUsers(users)

    const token = jwt.sign({id:newUser.id,email:newUser.email},SECRET_KEY,{expiresIn:'1h'})
    res.status(200).json({ message:'User registered successfully',token})})


// Login 
app.post('/login',async(req,res) => {
    const { email, password } = req.body
    if(!email || !password) return res.status(400).json({error:'Email and password are required'})
    const users = readUsers()
    const user = users.find((user) => user.email === email)
    if (!user || !(await bcrypt.compare(password, user.password)))
        return res.status(401).json({ error: 'Invalid credentials' })
    const token = jwt.sign({id:user.id,email:user.email},SECRET_KEY,{expiresIn:'1h'})
    res.json({message:'Login successful',token })
})

//  All Users 
app.get('/users',authenticateToken,(req,res) => {
    const users = readUsers().map(({ password,...rest })=>rest)
    res.json(users)
})

//  Users by ID 
app.get('/users/:id',authenticateToken,(req,res) => {
    const users = readUsers()
    const user = users.find((u)=>u.id==req.params.id)
    if (!user) return res.status(404).json({ error: 'User not found' })
    const { password, ...userDetails } = user
    res.json(userDetails)
})

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`)
})