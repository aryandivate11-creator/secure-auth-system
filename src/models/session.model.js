import mongoose, { Mongoose , model} from "mongoose";
import { refreshToken } from "../controllers/auth.controller.js";

const sessionSchema = new mongoose.Schema({
    user:{
        type :mongoose.Schema.Types.ObjectId,
        ref : "users",
        required : [true,"User is required"]
    },
    refreshTokenHash:{
        type:String,
        required:[true , "Refresh token is required"]
    },
    ip:{
        type : String,
        required : [true,"IP address is required"]
    },
    userAgent:{
        type:String,
        required:[true,"UserAgent is required"]
    },
    revoked:{
        type:Boolean,
        default:false
    }
},{
    timestamps:true
});

const sessionModel = mongoose.model("sessions",sessionSchema);

export default sessionModel;