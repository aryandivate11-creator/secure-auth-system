import mongoose from "mongoose";


const otpSchema = new mongoose.Schema({
    email: {
        type: String,
        required: [ true, "Email is required" ]
    },
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "users",
        required: [ true, "User is required" ]
    },
    otpHash: {
        type: String,
        required: [ true, "OTP hash is required" ]
    },
    expiresAt: {
      type: Date,
      required: true,
      expires: 0
   },
   attempts:{
    type:Number,
    default:0
   },
   blockedUntil:{
    type:Date,
    deafult:null
   },
   lastSentAt: {
   type: Date,
   default: Date.now
}
}, {
    timestamps: true
});

const otpModel = mongoose.model("OTP",otpSchema);

export default otpModel;