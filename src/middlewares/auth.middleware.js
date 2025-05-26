import { ApiError } from "../utils/ApiError"
import {asyncHandler} from "../utils/asyncHandler"
import jwt from "jsonwebtoken"
import {User} from "../models/user.models"



export const  verifyJWT=asyncHandler(async(req , res ,next)=>{
    try {
        const token=req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ","");
        
        if(!token){
            throw new ApiError(401,"unauthorized request");
        }
        const decodedTokrn=jwt.verify(token,process.env.ACCESS_TOKEN_SECRET);
    
        const user=await User.findById(decodedTokrn._id).select("-password -refreshToken");
    
        if(!user){
            throw new ApiError(401,"invalid accesstoken`");
        }
        req.user=user;
        next();
    } catch (error) {
        throw new ApiError(401,error?.message ||"invalid accesstoken");
    }
    
})