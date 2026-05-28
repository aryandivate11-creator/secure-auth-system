import jwt from "jsonwebtoken";
import config from "../config/config.js";

const authMiddleware = async(req,res,next) =>{
     try {

      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith("Bearer ")) {

         return res.status(401).json({
            message: "Unauthorized"
         });
      }

      const token = authHeader.split(" ")[1];

      const decoded = jwt.verify(
         token,
         config.JWT_SECRET
      );

      req.user = decoded;

      next();

   } catch (err) {

      return res.status(401).json({
         message: "Invalid token"
      });
   }
};

export default authMiddleware;