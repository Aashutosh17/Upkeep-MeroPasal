import sgMail from '@sendgrid/mail';
import sanitize from 'mongo-sanitize';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import { generateToken, verifyToken, returnTime } from '../utils/utils.js';
import {
    validateUsername,
    validateEmail,
    validatePassword,
} from '../utils/validation.js';
import User from '../models/user.model.js';
import { createError } from '../config/createError.js';
import bcrypt from 'bcryptjs';
import { sendMail } from '../utils/sendMail.js';
import asyncHandler from 'express-async-handler';
import Token from '../models/token.model.js';
import SendMail from '../utils/mail.js';

// config of sendgrid to send mail
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
const MAX_LOGIN_ATTEMPTS = 3; // Set the max login attempts before lockout
const LOCK_TIME = 1 * 60 * 60 * 1000; // Set the lock time (e.g., 1 hour)

export const authRegister = async (req, res, next) => {
    try {
        const email = sanitize(req.body.email);
        const username = sanitize(req.body.username);
        const password = sanitize(req.body.password);
        const address = sanitize(req.body.address);

        if (!email || !username || !password)
            return res.status(400).json({ msg: 'Please enter all fields! ' });

        const userExist = await User.findOne({
            $or: [{ username }, { email }],
        });

        if (userExist) {
            return res.status(403).json({
                msg: 'Email or Username is already taken ! Try using another.',
            });
        }
        if (username.length <= 6 || username.length > 15)
            return res.status(400).json({
                msg: "Username's character must be between 6 and 15 !",
            });
        if (!validateUsername(username))
            return res.status(400).json({
                msg: 'Username should be alphanumeric and not contain special characters !',
            });
        if (!validateEmail(email))
            return res
                .status(400)
                .json({ msg: 'Email address should be valid!' });


        const passwordValidation = validatePassword(password);
        if (!passwordValidation.isStrongPassword) {
            return res.status(400).json({
                msg: 'Password must be between 8 to 12 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.',
                passwordStrength: passwordValidation // Optionally return the password strength details
            });
        }
        const token = generateToken({ email, username, address, password });

        const link = `${process.env.CLIENT_URI}/auth/activate/${token}`;

        // send reset email
        const message = `
            <h2>Hello, ${username}</h2><br>
            <p>Please use the URL below to activate your account.</p>
            <p>Your reset link is valid for 30 minutes.</p>
            <br><br>
            <a href="${link}" clicktracking="off">${link}</a>
            <hr>
            <span>Regards...</span>
            <h3>Thank you...</h3>
        `;

        let subject = 'Activate your account | neeswebservices';
        let sendTo = email;
        let sendFrom = process.env.NOREPLY;

        const result = await SendMail(subject, message, sendTo, sendFrom);
        if (result) {
            return res.status(200).send({
                msg: `Token is valid for next 30 minutes :  ${returnTime(
                    new Date(Date.now() + 1000 * 1800),
                )}`,
            });
        } else {
            return res
                .status(500)
                .json({ success: false, message: 'Failed to send email.' });
        }

        // sendMail(email, link)
        //     .then((data) => {
        //         console.log(data);
        //         return res.json({
        //             msg: 'Please check your mail for activation link...',
        //         });
        //     })
        //     .catch((err) => {
        //         console.log(err);
        //         return res.status(408).json({
        //             msg: `Failed to send mail, Please try again later!`,
        //             link,
        //         });
        //     });
    } catch (err) {
        process.env.ENV == 'development' ? console.log(err) : null;
        return res.status(500).json({ msg: 'Something went wrong !' });
    }
};

export const userDetails = async (req, res, next) => {
    try {
        if (!req.user)
            return res.status(400).send({ msg: 'User unauthorized' });

        const { _doc } = await User.findById(req.user);

        return res.send({ ..._doc, role: req.role });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ msg: 'Invalid or token expired !' });
    }
};

export const authActivate = async (req, res, next) => {
    const { token } = req.params || req.body || req.headers['token'];
    try {
        if (!token)
            return res
                .status(403)
                .send({ success: false, msg: 'Invalid request !' });

        jwt.verify(token, process.env.AUTH_SECRET, async (err, result) => {
            if (err) return res.status(403).send({ msg: 'Unauthorized !' });
            const { username, address, email, password } = result;
            if (await User.findOne({ $or: [{ username, email }] }))
                return res.status(403).json({
                    msg: 'User Already Activated | Please Login !',
                });
            await User.create({
                username,
                email,
                address,
                password,
            })
                .then((msg) => {
                    return res
                        .status(201)
                        .send({ msg: 'User successfully activated !' });
                })
                .catch((err) => {
                    console.log(err);
                    return res.status(400).send({
                        msg: 'Failed to Activate user, Try again !',
                    });
                });
        });
    } catch (err) {
        console.log(err);
        // process.env.ENV == 'development' ? console.log(err) : null;
        return res.status(500).json({ msg: 'Invalid or token expired !' });
    }
};

export const verifyLogin = async (req, res, next) => {
    try {
        const { emailorusername, password } = req.body;

        if (!emailorusername || !password) {
            return next(createError('Email/Username and password are required.', 400));
        }

        const user = await User.findOne({
            $or: [{ email: emailorusername }, { username: emailorusername }],
        }).select('+password');

        if (!user) {
            return next(createError("User doesn't exist, please register.", 403));
        }

        // Check if the account is currently locked
        if (user.lockUntil && user.lockUntil > Date.now()) {
            return next(createError('This account is temporarily locked.', 403));
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (isMatch) {
            // Reset login attempts on successful login
            user.failedLoginAttempts = 0;
            user.lockUntil = undefined;
            await user.save();

            // User authentication succeeded
            const token = jwt.sign({ id: user._id }, process.env.SECRETTOKEN);
            res.cookie('accesstoken', token);
            return res.status(200).send({ token });
        } else {
            // Password is incorrect, increment failed login attempts
            user.failedLoginAttempts += 1;
            if (user.failedLoginAttempts >= MAX_LOGIN_ATTEMPTS) {
                // Lock the account if max attempts have been reached
                user.lockUntil = new Date(Date.now() + LOCK_TIME);
            }
            await user.save();

            // If the account is now locked, send a different message
            if (user.failedLoginAttempts >= MAX_LOGIN_ATTEMPTS) {
                return next(createError('Your account has been locked due to multiple failed login attempts.', 403));
            }

            return next(createError('Invalid password. Please try again.', 403));
        }
    } catch (err) {
        return next(createError('Login failed, please try again.', 500));
    }
};

export const logout = async (req, res, next) => {
    try {
        res.clearCookie('accesstoken');
        return res.status(200).send({ msg: 'Logged out successfully !' });
    } catch (error) {
        next(error);
    }
};

export const checkLogin = asyncHandler(async (req, res, next) => {
    console.log(req.user);

    if (req.user) {
        const user = await User.findById(req.user);
        return res
            .status(200)
            .send({ user, status: true, msg: 'User is logged' });
    }

    return next(createError('User not logged in !', 400));
});

export const forgotPassword = asyncHandler(async (req, res, next) => {
    try {
        const { email } = req.body;

        if (!email) return res.status(400).send({ msg: 'Invalid request!' });

        const userExist = await User.findOne({ email });

        if (!userExist) return res.status(404).send({ msg: 'User not found!' });

        // delete token if user exists
        const token = await Token.findOne({ userId: userExist._id });
        if (token) await Token.deleteOne();

        const resetToken =
            crypto.randomBytes(32).toString('hex') + userExist._id;

        const hashedToken = crypto
            .createHash('sha256')
            .update(resetToken)
            .digest('hex');

        const userToken = new Token({
            userId: userExist._id,
            token: hashedToken,
            createdAt: Date.now(),
            expiresAt: Date.now() + 1000 * 30 * 60,
        });

        await userToken.save();

        const link = `${process.env?.CLIENT_URI}/auth/reset/${resetToken}`;

        // send reset email
        const message = `
         <h2>Hello, ${email}</h2><br>
         <p>Please use the URL below to activate your account.</p>
         <p>Your reset link is valid for 30 minutes.</p>
         <br><br>
         <a href="${link}" clicktracking="off">${link}</a>
         <hr>
         <span>Regards...</span>
         <h3>Thank you...</h3>
     `;

        let subject = 'Activate your account | neeswebservices';
        let sendTo = email;
        let sendFrom = process.env.NOREPLY;

        const result = await SendMail(subject, message, sendTo, sendFrom);

        if (result) {
            return res.json({
                msg: 'Please check your mail for activation link...',
                resetToken,
            });
        } else {
            return res.status(408).json({
                msg: `Failed to send mail, Please try again later!`,
                resetToken,
            });
        }

        // return res.send({ userToken, resetToken });
    } catch (error) {
        next(error);
    }
});

// export const resetPassword = asyncHandler(async (req, res, next) => {
//     try {
//         const { password } = req.body;

//         const resetToken = req.body?.resetToken || req.params?.resetToken;

//         if (!resetToken)
//             return res.status(400).send({ msg: 'Invalid Request !' });

//         const hashedToken = crypto
//             .createHash('sha256')
//             .update(resetToken)
//             .digest('hex');

//         const userToken = await Token.findOne({
//             token: hashedToken,
//             expiresAt: { $gt: Date.now() },
//         });

//         if (!userToken)
//             return res.status(404).send({ msg: 'Invalid or expired token!' });
//         if (!validatePassword(password))
//             return res.status(400).send({
//                 msg: 'Password should contain one uppercase, symbol, number and atleast 8 characters',
//             });

//         const { userId } = userToken;

//         const hashedPassword = await bcrypt.hash(password, 12);
//         const user = await User.findByIdAndUpdate(
//             userId,
//             {
//                 password: hashedPassword,
//             },
//             {
//                 new: true,
//                 runValidators: true,
//             },
//         );
//         if (user) userToken.deleteOne();

//         return res.send({ msg: 'Password successfully reset!' });
//     } catch (error) {
//         next(error);
//     }
// });

export const resetPassword = asyncHandler(async (req, res, next) => {
    try {
        const { password } = req.body;
        const resetToken = req.body?.resetToken || req.params?.resetToken;

        if (!resetToken) {
            return res.status(400).send({ msg: 'Invalid Request !' });
        }

        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        const userToken = await Token.findOne({
            token: hashedToken,
            expiresAt: { $gt: Date.now() },
        });

        if (!userToken) {
            return res.status(404).send({ msg: 'Invalid or expired token!' });
        }

        if (!validatePassword(password)) {
            return res.status(400).send({
                msg: 'Password should contain one uppercase, symbol, number and at least 8 characters',
            });
        }

        const user = await User.findById(userToken.userId);
        if (!user) {
            return res.status(404).send({ msg: 'User not found!' });
        }

        if (!(await user.isPasswordUnique(password))) {
            return res.status(400).send({ msg: 'You cannot reuse your recent passwords.' });
        }

        // If the password is unique, proceed to hash and set the new password
        const hashedPassword = await bcrypt.hash(password, 12);
        user.password = hashedPassword;
        await user.save();

        // Clear the reset token
        await userToken.deleteOne();

        res.send({ msg: 'Password successfully reset!' });
    } catch (error) {
        next(error);
    }
});


export const getAccessToken = async (req, res, next) => { };

export const generateRefreshToken = async (req, res, next) => { };
