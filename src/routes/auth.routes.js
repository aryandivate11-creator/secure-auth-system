import { Router } from "express";
import * as authController from "../controllers/auth.controller.js"
import authMiddleware from "../middlewares/auth.middleware.js";

const authRouter = Router();

authRouter.post("/register",authController.register);

authRouter.post("/login",authController.login);

authRouter.get("/get-Me", authMiddleware, authController.getMe);

authRouter.get("/refresh-token",authController.refreshToken);

authRouter.get("/logout",authController.logout);

authRouter.get("/logout-all",authController.logoutAll);

authRouter.post("/verify-email", authController.verifyEmail);

authRouter.post("/resend-otp",authController.resendOtp);

export default authRouter;