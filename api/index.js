import express from "express"
import cors from "cors"
import dotenv from "dotenv"
dotenv.config();
import connectDB from "./config/db.js";
import User from "./models/userModel.js";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"


const app = express();

connectDB();  //connection to database

const salt = await bcrypt.genSalt(10);

app.use(express.json())
app.use(express.urlencoded({extended:true}))

app.use(cors({
    credentials:true,
    origin:'http://localhost:5173'
}));

const jwtSecret = process.env.Secret;

app.get('/test',(req,res) => {
    res.json('test ok')
});

app.post('/register', async (req,res)=>{
    const {name,email,password} = req.body;
    const userDoc = await User.create({
        name,
        email,
        password:bcrypt.hashSync(password,salt)
    })
    res.json(userDoc);
})

app.post('/login', async (req,res) => {
    const {email,password} = req.body;
    const userDoc = await User.findOne({email});
    if(userDoc){
        const passOk = bcrypt.compareSync(password, userDoc.password)
        if(passOk){
            jwt.sign({email:userDoc.email,id:userDoc._id},jwtSecret,{},(err,token) => {
                if (err) throw err;
                res.cookie('token',token,{
                    secure:true,
                    sameSite:'none'
                }).json('pass ok')
            })
            
        }
        else{
            res.status(422).json('pass not ok')
        }
    } else{
        res.json('user not exist')
    }
})

app.listen(4000);