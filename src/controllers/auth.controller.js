import userModel from "../models/user.model.js";
import crypto from "crypto";
import config from "../config/config.js";
import jwt from "jsonwebtoken";
import sessionModel from "../models/session.model.js";
import authRouter from "../routes/auth.routes.js";
import { sendEmail } from "../services/email.service.js";
import { generateOtp , getOtpHTML } from "../utils/utils.js";
import otpModel from "../models/otp.model.js";

export const register = async (req, res) => {

    try {

        const { email, username, password } = req.body;

        const isAlreadyRegistered = await userModel.findOne({
            $or: [
                { username },
                { email }
            ]
        });

        if (isAlreadyRegistered) {
            return res.status(409).json({
                message: "Username or email already exists"
            });
        }

        const hashedPassword = crypto
            .createHash("sha256")
            .update(password)
            .digest("hex");
        
        const user = await userModel.create({
            username,
            email,
            password: hashedPassword
        });
        
        const otp = generateOtp();
        const html = getOtpHTML(otp);
        
        const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

        await otpModel.create({
            email,
            user: user._id,
            otpHash
        })
        await sendEmail(email,"OTP verification",`Your otp is ${otp}`,html)
        // const refreshToken = jwt.sign(
        //     {
        //         id:user._id
        //     },
        //     config.JWT_SECRET,
        //     {
        //         expiresIn:"7d"
        //     }
        // );
        
        // const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex")

        // const session = sessionModel.create({
        //     user:user._id,
        //     refreshTokenHash,
        //     ip:req.ip,
        //     userAgent:req.headers["user-agent"]
        // });
        
        // const accessToken = jwt.sign(
        //     {
        //         id: user._id,
        //         sessionId: session._id
        //     },
        //     config.JWT_SECRET,
        //     {
        //         expiresIn: "15m"
        //     }
        // );

        // res.cookie("refreshToken",refreshToken ,{
        //     httponly : true,
        //     secure : false,
        //     sameSite : "strict",
        //     maxAge : 7 * 24  * 60 * 60 * 1000
        // });
        

        res.status(201).json({
            message: "User registered successfully",
            user: {
                username: user.username,
                email: user.email,
                verified:user.verified
            }
        });

    } catch (error) {

            console.log(error);

        return res.status(500).json({
            message: "Internal server error",
            error: error.message
        });
    }
};

export const login = async(req,res) =>{
      const {email, password} = req.body;

      const user = await userModel.findOne({email});

      if(!user){
        return res.status(401).json({
            message:"User Does not Exists"
        });
      };

      if(!user.verified){
        return res.status(401).json({
            message:"Email is not verified"
        });
      };

      const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");

      const isPasswordValid = hashedPassword == user.password;

      if(!isPasswordValid){
        return res.status(401).json({
            message:"Enter correct password"
        });
      };
      
      const refreshToken = jwt.sign({
         id : user._id
      },config.JWT_SECRET,
       {
            expiresIn:"7d"
      });

      const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

      const session = sessionModel.create({
            user:user._id,
            refreshTokenHash,
            ip:req.ip,
            userAgent:req.headers["user-agent"]
        });

      const accessToken = jwt.sign({
         id :user._id
      },config.JWT_SECRET,
       {
            expiresIn:"15m"
      });

       res.cookie("refreshToken",refreshToken ,{
            httponly : true,
            secure : false,
            sameSite : "strict",
            maxAge : 7 * 24  * 60 * 60 * 1000
        });

       res.status(201).json({
        message:"User Logged in successfully",
        user:{
           username:user.username,
           email:user.email,
        },
        accessToken
       })
};

export const getMe  = async (req,res) =>{
};

export const refreshToken = async (req,res) =>{
    const refreshToken = req.cookies.refreshToken;

    console.log(req.cookies);

    if(!refreshToken){
        return res.status(401).json({
            message:"refresh token not found"
        });
    };

    const decoded = jwt.verify(refreshToken,config.JWT_SECRET);
    
    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");
    
     const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked:false
    });

    if(!session){
        return res.status(400).json({
            message:"Invalid refresh Tokn"
        })
    };

    const accessToken = jwt.sign({
        id : decoded.id
    },config.JWT_SECRET,
    {
        expiresIn:"15m"
    }
   );
    
   const newRefreshToken = jwt.sign({
        id : decoded.id
    },config.JWT_SECRET,
    {
        expiresIn:"7d"
    });
    
   const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");

   session.refreshTokenHash = newRefreshTokenHash;
   await session.save();



    res.cookie("refreshToken",newRefreshToken,{
       httpOnly:true,
       secure:false,
       sameSite:"strict",
       maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days 
    });

    res.status(200).json({
        message:"Access Token refreshed successfully !",
        accessToken
    });

};

export const logout = async(req,res) =>{

    const refreshToken = req.cookies.refreshToken

    if(!refreshToken){
        return res.status(401).json({
            message:"No Refresh token"
        })
    }

    const refreshTokenHash = crypto.createHash("sha256").update(refreshToken).digest("hex");

    const session = await sessionModel.findOne({
        refreshTokenHash,
        revoked:false
    });

    if(!session){
        return res.status(400).json({
            message:"Invalid refresh Tokn"
        })
    };

    session.revoked = true
    await session.save();

    res.clearCookie("refreshToken");

    res.status(200).json({
        message:"Logged Out successfully !"
    });
};

export const logoutAll = async(req,res) =>{
    const refreshToken = req.cookies.refreshToken;

    if(!refreshToken){
        return res.status(401).json({
            message:"Refresh Token not Found"
        });
    };

    const decoded = jwt.verify(refreshToken,config.JWT_SECRET);

    await sessionModel.updateMany({
        user:decoded.id,
        revoked:false
    },{
        revoked:true
    });

    res.clearCookie("refreshToken");

    res.status(200).json({
        message:"Logged out from all devices successfully"
    })
};

export const verifyEmail = async(req,res) =>{
    console.log(req.body,)
      const {otp,email} = req.body;

      const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

      const otpDoc = await otpModel.findOne({
        email,
        otpHash
      });

      if(!otpDoc){
        return res.status(401).json({
            message:"Invlaid OTP"
        });
      };

      const user = await userModel.findByIdAndUpdate(otpDoc.user,{
        verified:true
      });

      await otpModel.deleteMany({
        user : otpDoc.user
      });

      return res.status(200).json({
        message:"Email verified successfully",
        user:{
            username:user.username,
            email:user.email,
            verified:user.verified
        }
      })
};