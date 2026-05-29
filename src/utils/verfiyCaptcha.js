import axios from "axios";
import config from "../config/config.js";

const verifyCaptcha = async (token) => {

   try {

      const response = await axios.post(
         `https://www.google.com/recaptcha/api/siteverify`,
         null,
         {
            params: {
               secret: config.RECAPTCHA_SECRET_KEY,
               response: token
            }
         }
      );

      return response.data.success;

   } catch (error) {

      console.log(error);

      return false;
   }
};

export default verifyCaptcha;