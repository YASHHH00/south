import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import crypto from "crypto";
const userSchema = new Schema({

    username:{
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        index: true
    },
    email:{
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        index: true
    },
    password:{
        type: String,
        required: [true,"Password is required"],
    },
    isEmailVerified:{
        type: Boolean,
        default: false
    },
    forgotPasswordToken:{
        type: String,
    },
    forgotPasswordExpiry:{
        type: Date
    },
    refreshToken:{
        type: String
    },
    emailVerificationToken:{
        type: String
    },
    emailVerificationExpiry:{
        type: Date
    },
},
{    timestamps: true},
);

// IMPORTANT: Always hash passwords before saving to database
// This mongoose pre-save hook ensures passwords are never stored in plain text
// Only hash if password field is modified (prevents re-hashing on every save)
userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) {
        return next();
    }
    // IMPORTANT: Use bcrypt with salt rounds >= 10 for security
    // Higher rounds = more secure but slower (10 is industry standard)
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

// IMPORTANT: Always use bcrypt.compare for password verification
// Never compare plain text passwords - this prevents timing attacks
// bcrypt.compare is constant-time, preventing time-based side-channel attacks
userSchema.methods.isPasswordCorrect = async function(password) {
    return await bcrypt.compare(password, this.password);
};

// IMPORTANT: Access tokens should be short-lived (15min - 1hr typically)
// Long-lived access tokens increase security risk if compromised
// Use refresh tokens for longer sessions
userSchema.methods.generateAccessToken = function() {
    // IMPORTANT: Always validate environment variables exist
    // Missing secret causes JWT signing to fail silently
    if (!process.env.ACCESS_TOKEN_SECRET) {
        throw new Error("ACCESS_TOKEN_SECRET environment variable is not set");
    }
    
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username
        },
        process.env.ACCESS_TOKEN_SECRET,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY || "1h" // Default to 1 hour if not set
        }
    );
};

// IMPORTANT: Refresh tokens should be long-lived (7-30 days typically)
// Used to obtain new access tokens without re-authentication
userSchema.methods.generateRefreshToken = function() {
    if (!process.env.REFRESH_TOKEN_SECRET) {
        throw new Error("REFRESH_TOKEN_SECRET environment variable is not set");
    }
    
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            username: this.username
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY || "7d" // Default to 7 days if not set
        }
    );
};

// IMPORTANT: Temporary tokens (for email verification, password reset) must:
// 1. Be cryptographically random (crypto.randomBytes)
// 2. Be hashed before storing in database (SHA-256)
// 3. Have explicit expiry times (15 min for security)
// Store hashed version in DB, send plain version in email
userSchema.methods.generateTemporaryToken = function() {
    // IMPORTANT: Use crypto.randomBytes for secure random token generation
    // Math.random() is NOT cryptographically secure
    const unHashedToken = crypto.randomBytes(20).toString("hex");

    // IMPORTANT: Always hash tokens before storing in database
    // If database is compromised, hashed tokens can't be used directly
    const hashedToken = crypto.createHash("sha256").update(unHashedToken).digest("hex");
    
    // IMPORTANT: Set explicit expiry time (15 minutes for security-sensitive operations)
    // Prevents old tokens from being reused
    const tokenExpiry = Date.now() + 15 * 60 * 1000; // 15 minutes

    return { unHashedToken, hashedToken, tokenExpiry };
};


export const User = mongoose.model("User", userSchema);