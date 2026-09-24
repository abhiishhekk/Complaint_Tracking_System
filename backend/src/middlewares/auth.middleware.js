import { User } from '../models/user.model.js';
import { apiError } from '../utils/apiError.js';
import { asyncHandler } from '../utils/asyncHandler.js';
import jwt from 'jsonwebtoken';

export const verifyJWT = asyncHandler(async (req, res, next) => {
  const accessToken = req.headers.authorization?.replace("Bearer ", "");

  const { refreshToken } = req.cookies;

  if (!accessToken && !refreshToken) {
    throw new apiError(401, "Unauthorized request: No tokens provided");
  }

  // First, try to verify the accessToken
  try {
    if (!accessToken) {
        throw new Error("Access token missing");
    }

    const decodedToken = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
    const user = await User.findById(decodedToken?._id).select("-password -refreshToken");

    if (!user) {
      throw new apiError(401, "Invalid Access Token: User not found");
    }

    req.user = user;
    return next(); // User is verified, proceed to the next middleware/controller

  } catch (error) {
    // If accessToken is expired or invalid, we'll try to use the refreshToken
    // We only proceed if a refreshToken exists
    if (!refreshToken) {
        throw new apiError(401, "Session expired. Please log in again.");
    }
  }

  // If the access token verification failed, try to refresh it using the refresh token
  try {
    const decodedRefreshToken = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decodedRefreshToken?._id);

    if (!user) {
        throw new apiError(401, "Invalid Refresh Token: User not found");
    }

    // Security check: Ensure the refresh token from the cookie matches the one in the database
    if (user.refreshToken !== refreshToken) {
      throw new apiError(401, "Refresh token is expired or has been used");
    }
    
    // Refresh Token Rotation (RTR):
    // Generate a fresh access token and rotate the refresh token
    const newAccessToken = user.generateAccessToken();
    const newRefreshToken = user.generateRefreshToken();

    // Persist rotated refresh token to database
    user.refreshToken = newRefreshToken;
    await user.save({ validateBeforeSave: false });

    // Set rotated refresh token in secure cookie
    const cookieOptions = {
      httpOnly: process.env.COOKIE_HTTP_ONLY === 'true' || process.env.COOKIE_HTTP_ONLY === true,
      secure: process.env.COOKIE_SECURE === 'true' || process.env.COOKIE_SECURE === true,
      sameSite: process.env.COOKIE_SAME_SITE || 'None',
    };
    res.cookie('refreshToken', newRefreshToken, cookieOptions);

    // Attach the new access token to the custom response header
    res.setHeader('x-access-token', newAccessToken);

    user.password = undefined;
    req.user = user;
    next();
    
  } catch (refreshError) {
    if (refreshError instanceof apiError) {
      throw refreshError;
    }
    // If the refresh token is also invalid or expired
    throw new apiError(401, refreshError.message || "Session expired. Please log in again.");
  }
});