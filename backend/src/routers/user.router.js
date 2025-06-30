import { Router } from "express";
import auth from '../middleware/auth.mid.js';
import pkg from 'jsonwebtoken';
const jwt = pkg;
const router = Router();
import { BAD_REQUEST } from "../constants/httpStatus.js";
import handler from "express-async-handler";
import { UserModel } from "../models/user.model.js";
import bcrypt from 'bcryptjs';
const PASSWORD_HASH_SALT_ROUNDS=10; 
router.post('/login',handler(async (req,res)=>{
 const {email,password} = req.body;
 const user= await UserModel.findOne({email});
 if(user && (await bcrypt.compare(password, user.password))){
    res.send(generateTokenResponse(user));
    return;
}
res.status(BAD_REQUEST).send('Username or password is invalid');
}));
router.post(
    '/register',
    handler(async (req,res)=>{
        const {name,email,password,address}=req.body;
        const user=await UserModel.findOne({email});
        if(user){
            res.status(BAD_REQUEST).send('User already exists, please login!');
            return;
        }

        const hashedPassword=await bcrypt.hash(password,PASSWORD_HASH_SALT_ROUNDS);
        const newUser={
            name,
            email: email.toLowerCase(),
            password:hashedPassword,
            address,
        };
        const result=await UserModel.create(newUser);
        res.send(generateTokenResponse(result));
    })
);

const generateTokenResponse=user=>{
    const token=jwt.sign({
        id:user.id, email:user.email, isAdmin:user.isAdmin,
    }, process.env.JWT_SECRET,{
        expiresIn:'30d',
    });
    return{
        id:user.id,
        name:user.name,
        email:user.email,
        address:user.address,
        isAdmin:user.isAdmin,
        token,
    };
};
router.put(
    '/changePassword',
    auth,
    handler(async (req, res) => {
        const { currentPassword, newPassword } = req.body;
        const user = await UserModel.findById(req.user.id);
        
        if (!(await bcrypt.compare(currentPassword, user.password))) {
            res.status(BAD_REQUEST).send('Current password is incorrect');
            return;
        }

        user.password = await bcrypt.hash(newPassword, PASSWORD_HASH_SALT_ROUNDS);
        await user.save();
        
        res.send();
    })
);

router.put(
    '/updateProfile',
    auth,
    handler(async (req, res) => {
        const { name, address } = req.body;
        const user = await UserModel.findById(req.user.id);

        user.name = name;
        user.address = address;
        await user.save();

        res.send(generateTokenResponse(user));
    })
);

export default router;