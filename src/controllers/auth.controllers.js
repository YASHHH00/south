import { asyncHandler } from "../utils/async-handler.js";
import { ApiError } from "../utils/api-error.js";
import { ApiResponse } from "../utils/api-response.js";
import { User } from "../models/user.models.js";
import sendEmail from "../utils/mail.js";
import crypto from "crypto";

// IMPORTANT: Always wrap async controller functions with asyncHandler
// This prevents unhandled promise rejections from crashing the server
// Without asyncHandler, errors in async functions won't be caught by error middleware

/**
 * Register a new user
 * IMPORTANT: Always hash passwords before storing in database
 * Never store plain text passwords - use bcrypt with salt rounds >= 10
 */
export const registerUser = asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;

    // IMPORTANT: Always check if user already exists before creating
    // Prevents duplicate accounts and provides clear error messages
    const existingUser = await User.findOne({
        $or: [{ username }, { email }]
    });

    if (existingUser) {
        throw new ApiError(409, "User with this username or email already exists");
    }

    // IMPORTANT: Generate email verification token before creating user
    // Users must verify email before accessing full features
    const { unHashedToken, hashedToken, tokenExpiry } = new User().generateTemporaryToken();

    const user = await User.create({
        username: username.toLowerCase(),
        email: email.toLowerCase(),
        password, // Password will be hashed by pre-save hook in user model
        emailVerificationToken: hashedToken,
        emailVerificationExpiry: tokenExpiry
    });
    const verificationUrl = `http://localhost:8000/api/v1/auth/verify/${unHashedToken}`;
  // 5️⃣ Print the verification link in console
    console.log("👇 Email Verification Link (copy and paste in browser):");
    console.log(verificationUrl);

    // IMPORTANT: Remove sensitive data before sending response
    // Never send passwords, tokens, or internal IDs to clients
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken -forgotPasswordToken -emailVerificationToken"
    );

    if (!createdUser) {
        throw new ApiError(500, "Error creating user. Please try again.");
    }

    // TODO: Send verification email with unHashedToken
    // IMPORTANT: Send unHashedToken in email, not hashedToken
    // Email should contain the token user can click

    return res.status(201).json(
        new ApiResponse(201, createdUser, "User registered successfully. Please verify your email.")
    );
});

/**
 * Login user
 * IMPORTANT: Always use secure password comparison (bcrypt.compare)
 * Never compare plain text passwords directly
 */
export const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // IMPORTANT: Always validate user exists before checking password
    // Don't reveal if email exists - use generic "Invalid credentials" message
    // But for this codebase, we'll be explicit for now (can be improved)
    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
        throw new ApiError(401, "Invalid email or password");
    }

    // IMPORTANT: Always verify password using model method (bcrypt.compare)
    // This prevents timing attacks compared to plain text comparison
    const isPasswordValid = await user.isPasswordCorrect(password);

    if (!isPasswordValid) {
        throw new ApiError(401, "Invalid email or password");
    }

    // IMPORTANT: Generate access and refresh tokens
    // Access tokens for short-lived API access, refresh tokens for re-authentication
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    // IMPORTANT: Store refresh token in database
    // Needed for token refresh and logout functionality
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });

    // IMPORTANT: Set secure cookie options in production
    // HttpOnly prevents XSS attacks, Secure ensures HTTPS only, SameSite prevents CSRF
    const options = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict"
    };

    // IMPORTANT: Remove sensitive data before sending response
    const loggedInUser = await User.findById(user._id).select(
        "-password -refreshToken -forgotPasswordToken -emailVerificationToken"
    );

    return res
        .status(200)
        .cookie("accessToken", accessToken, options)
        .cookie("refreshToken", refreshToken, options)
        .json(
            new ApiResponse(
                200,
                {
                    user: loggedInUser,
                    accessToken, // Also send in response for non-cookie clients
                    refreshToken
                },
                "User logged in successfully"
            )
        );
});

/**
 * Get current user profile
 * IMPORTANT: Always verify user is authenticated before accessing profile
 * This endpoint requires isLoggedIn middleware
 */
export const getMe = asyncHandler(async (req, res) => {
    // IMPORTANT: User is attached to req by auth middleware
    // No need to query database again - use req.user
    return res.status(200).json(
        new ApiResponse(200, req.user, "User profile fetched successfully")
    );
});

/**
 * Verify user email
 * IMPORTANT: Always hash tokens before comparing in database
 * Never compare plain tokens - prevents token database leaks from being exploited
 */
export const verifyUser = asyncHandler(async (req, res) => {
    const { token } = req.params;

    // IMPORTANT: Hash the token from URL before comparing with database
    // Database stores hashed token, so we must hash incoming token too
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
        emailVerificationToken: hashedToken,
        emailVerificationExpiry: { $gt: Date.now() }
    });

    if (!user) {
        throw new ApiError(400, "Invalid or expired verification token");
    }

    // IMPORTANT: Clear verification token after successful verification
    // Prevents reuse of verification tokens
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpiry = undefined;
    await user.save({ validateBeforeSave: false });

    return res.status(200).json(
        new ApiResponse(200, {}, "Email verified successfully")
    );
});

/**
 * Logout user
 * IMPORTANT: Always invalidate refresh tokens on logout
 * Prevents token reuse after user logs out
 */
export const logoutUser = asyncHandler(async (req, res) => {
    // IMPORTANT: Clear refresh token from database
    // Without this, token remains valid even after logout
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken: undefined
            }
        },
        { new: true }
    );

    const options = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "strict"
    };

    // IMPORTANT: Clear cookies on logout
    // Prevents client-side token reuse
    return res
        .status(200)
        .clearCookie("accessToken", options)
        .clearCookie("refreshToken", options)
        .json(new ApiResponse(200, {}, "User logged out successfully"));
});

/**
 * Request password reset
 * IMPORTANT: Don't reveal if email exists (security best practice)
 * But for simplicity, we'll show if email doesn't exist
 */
export const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;

    const user = await User.findOne({ email: email.toLowerCase() });

    if (!user) {
        throw new ApiError(404, "User with this email does not exist");
    }

    // IMPORTANT: Generate reset token with expiry
    // Store hashed token in database, send plain token in email
    const { unHashedToken, hashedToken, tokenExpiry } = user.generateTemporaryToken();

    user.forgotPasswordToken = hashedToken;
    user.forgotPasswordExpiry = tokenExpiry;
    await user.save({ validateBeforeSave: false });
    const resetUrl = `http://localhost:8000/api/v1/auth/reset-password/${unHashedToken}`;

   const htmlMessage = `
    <h2>Password Reset Request</h2>
    <p>You requested to reset your password. Click the link below to reset it:</p>
    <a href="${resetUrl}" target="_blank">Reset Password</a>
    <p>This link will expire in 10 minutes.</p>
  `;

  await sendEmail({
    email: user.email,
    subject: "Password Reset Request",
    html: htmlMessage,
  });


    // TODO: Send password reset email with unHashedToken
    // IMPORTANT: Include reset link with token in email
    return res.status(200).json(
        new ApiResponse(200, {}, "Password reset email sent successfully")
    );
});

/**
 * Reset password with token
 * IMPORTANT: Always verify token and expiry before allowing password reset
 * Expired or invalid tokens must be rejected
 */
export const resetPassword = asyncHandler(async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;

    // IMPORTANT: Hash incoming token before comparing with database
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
        forgotPasswordToken: hashedToken,
        forgotPasswordExpiry: { $gt: Date.now() }
    });

    if (!user) {
        throw new ApiError(400, "Invalid or expired password reset token");
    }

    // IMPORTANT: Update password and clear reset token
    // Password will be hashed by pre-save hook
    user.password = newPassword;
    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;
    await user.save();

    return res.status(200).json(
        new ApiResponse(200, {}, "Password reset successfully")
    );
});

