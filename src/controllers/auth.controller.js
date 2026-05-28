import userModel from "../models/user.model.js";
import crypto from "crypto";
import bcrypt from "bcrypt";
import config from "../config/config.js";
import jwt from "jsonwebtoken";
import sessionModel from "../models/session.model.js";
import authRouter from "../routes/auth.routes.js";
import { sendEmail } from "../services/email.service.js";
import { generateOtp , getOtpHTML } from "../utils/utils.js";
import otpModel from "../models/otp.model.js";

export const register = async (req, res) =>{

    try {

        const { email, username, password } = req.body;

        // =========================
        // Empty field validation
        // =========================

        if (!email || !username || !password) {
            return res.status(400).json({
                message: "All fields are required"
            });
        }

        // =========================
        // Trim values
        // =========================

        const trimmedEmail = email.trim().toLowerCase();
        const trimmedUsername = username.trim();

        // =========================
        // Email validation
        // =========================

        const emailRegex =
            /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(trimmedEmail)) {
            return res.status(400).json({
                message: "Invalid email format"
            });
        }

        // =========================
        // Username validation
        // =========================

        if (trimmedUsername.length < 3) {
            return res.status(400).json({
                message: "Username must be at least 3 characters long"
            });
        }

        if (trimmedUsername.length > 20) {
            return res.status(400).json({
                message: "Username cannot exceed 20 characters"
            });
        }

        // only letters, numbers, underscore

        const usernameRegex = /^[a-zA-Z0-9_]+$/;

        if (!usernameRegex.test(trimmedUsername)) {
            return res.status(400).json({
                message:
                    "Username can only contain letters, numbers and underscores"
            });
        }

        // =========================
        // Password validation
        // =========================

        if (password.length < 8) {
            return res.status(400).json({
                message:
                    "Password must be at least 8 characters long"
            });
        }

        // At least:
        // 1 uppercase
        // 1 lowercase
        // 1 number
        // 1 special character

        const passwordRegex =
            /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;

        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                message:
                    "Password must contain uppercase, lowercase, number and special character"
            });
        }

        // =========================
        // Existing user check
        // =========================

        const isAlreadyRegistered = await userModel.findOne({
            $or: [
                { username: trimmedUsername },
                { email: trimmedEmail }
            ]
        });

        if (isAlreadyRegistered) {
            return res.status(409).json({
                message: "Username or email already exists"
            });
        }

        // =========================
        // Hash password
        // =========================

        // const hashedPassword = crypto
        //     .createHash("sha256")
        //     .update(password)
        //     .digest("hex");

        const hashedPassword = await bcrypt.hash(password, 10);

        // =========================
        // Create user
        // =========================

        const user = await userModel.create({
            username: trimmedUsername,
            email: trimmedEmail,
            password: hashedPassword
        });

        // =========================
        // Generate OTP
        // =========================

        const otp = generateOtp();

        const html = getOtpHTML(otp);

        const otpHash = crypto
            .createHash("sha256")
            .update(otp)
            .digest("hex");
        
        await otpModel.deleteMany({
        email: trimmedEmail
        });

        await otpModel.create({
            email: trimmedEmail,
            user: user._id,
            otpHash,
            expiresAt: new Date(Date.now() + 5 * 60 * 1000)
        });

        await sendEmail(
            trimmedEmail,
            "OTP verification",
            `Your otp is ${otp}`,
            html
        );

        // =========================
        // Success response
        // =========================

        res.status(201).json({
            message: "User registered successfully",
            user: {
                username: user.username,
                email: user.email,
                verified: user.verified
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

      const isPasswordValid = await bcrypt.compare(
        password,
        user.password
        );

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

      const session = await sessionModel.create({
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

export const getMe = async(req,res) =>{

   const user = await userModel.findById(req.user.id)
      .select("-password");

   if (!user) {
      return res.status(404).json({
         message: "User not found"
      });
   }

   return res.status(200).json({
      user
   });
};

export const refreshToken = async(req,res) =>{
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

    const {otp,email} = req.body;

      const otpHash = crypto.createHash("sha256").update(otp).digest("hex");

      const otpDoc = await otpModel.findOne({
        email
      });

      console.log(otpDoc);

      if(!otpDoc){
        return res.status(401).json({
            message:"Invlaid OTP"
        });
      };

      const createdAt = otpDoc.createdAt.getTime();

      const isExpired =
      Date.now() - createdAt > 1 * 60 * 1000;

      if (isExpired) {

        await otpModel.deleteMany({
            user: otpDoc.user
        });

        return res.status(400).json({
            message: "OTP expired"
        });
        };

      const user = await userModel.findByIdAndUpdate(
        otpDoc.user,
        {
            verified: true
        },
        {
            new: true
        }
        );

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

export const resendOtp = async (req, res) => {

   try {

      const { email } = req.body;

      // =========================
      // Validation
      // =========================

      if (!email) {
         return res.status(400).json({
            message: "Email is required"
         });
      }

      // =========================
      // Find user
      // =========================

      const user = await userModel.findOne({ email });

      if (!user) {
         return res.status(404).json({
            message: "User not found"
         });
      }

      // =========================
      // Already verified
      // =========================

      if (user.verified) {
         return res.status(400).json({
            message: "User already verified"
         });
      }

      // =========================
      // Find existing OTP doc
      // =========================

      let otpDoc = await otpModel.findOne({
         user: user._id
      });

      // =========================
      // Check cooldown
      // =========================

      if (
         otpDoc &&
         otpDoc.blockedUntil &&
         otpDoc.blockedUntil > Date.now()
      ) {

         const remainingTime = Math.ceil(
            (otpDoc.blockedUntil.getTime() - Date.now())
            / 1000
         );

         return res.status(429).json({
            message:
               `Too many requests. Try again in ${remainingTime} seconds`
         });
      }

      // =========================
      // Reset cooldown if expired
      // =========================

      if (
         otpDoc &&
         otpDoc.blockedUntil &&
         otpDoc.blockedUntil <= Date.now()
      ) {
         otpDoc.blockedUntil = null;
      }

      // =========================
      // Generate new OTP
      // =========================

      const otp = generateOtp();

      const otpHash = crypto
         .createHash("sha256")
         .update(otp.toString())
         .digest("hex");

      // =========================
      // If otpDoc doesn't exist
      // create new one
      // =========================
      const cooldownTime = 30 * 1000;

        if (
        otpDoc &&
        Date.now() - otpDoc.lastSentAt.getTime()
        < cooldownTime
        ) {

        const remainingTime = Math.ceil(
            (
                cooldownTime -
                (Date.now() - otpDoc.lastSentAt.getTime())
            ) / 1000
        );

        return res.status(429).json({
            message:
                `Please wait ${remainingTime} seconds before requesting another OTP`
        });
        };

      if (!otpDoc) {

         otpDoc = await otpModel.create({
            email,
            user: user._id,
            otpHash,
            attempts: 1,
            blockedUntil: null,
            expiresAt: new Date(
               Date.now() + 5 * 60 * 1000
            )
         });

      } else {

         // =========================
         // Increment attempts
         // =========================

         otpDoc.attempts += 1;

         // =========================
         // Block after 5 attempts
         // =========================

         if (otpDoc.attempts >= 5) {

            otpDoc.blockedUntil =
               new Date(Date.now() + 2 * 60 * 1000);

            otpDoc.attempts = 0;

            await otpDoc.save();

            return res.status(429).json({
               message:
                  "Too many OTP requests. Try again in 2 minutes."
            });
         }

         // =========================
         // Update OTP doc
         // =========================

         otpDoc.otpHash = otpHash;

         otpDoc.expiresAt =
            new Date(Date.now() + 5 * 60 * 1000);
        
         otpDoc.lastSentAt = new Date();

         await otpDoc.save();
      }

      // =========================
      // Send email
      // =========================

      await sendEmail(
         email,
         "OTP verification",
         `Your otp is ${otp}`,
         getOtpHTML(otp)
      );

      return res.status(200).json({
         message: "OTP resent successfully"
      });

   } catch (error) {

      console.log(error);

      return res.status(500).json({
         message: "Internal server error"
      });
   }
};