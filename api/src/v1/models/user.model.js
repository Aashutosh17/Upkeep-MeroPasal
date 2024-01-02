import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const userSchema = new mongoose.Schema(
    {
        name: { type: String },
        username: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
        },
        address: { type: String },
        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
        },
        role: {
            type: Number,
            default: 0, // 0 - simple user, 1 - vendor , 2 - admin
            select: false,
        },
        password: {
            type: String,
            required: true,
            select: false,
        },
        failedLoginAttempts: {
            type: Number,
            required: true,
            default: 0,
        },
        lockUntil: {
            type: Date,
        },
        passwordHistory: [{
            passwordHash: String,
            changedAt: {
                type: Date,
                default: Date.now
            }
        }],
        vendorAccess: {
            type: Boolean,
            default: false,
        },
        phone: String,
        business_name: {
            type: String,
        },
        business_address: {
            type: String,
        },
        profile: {
            type: String,
            default:
                'https://upload.wikimedia.org/wikipedia/commons/thumb/5/59/User-avatar.svg/2048px-User-avatar.svg.png',
        },
        panno: { type: String },
    },
    {
        timestamps: true,
    },
);

userSchema.pre('save', async function (next) {
    if (this.isModified('password')) {
        const salt = await bcrypt.genSalt(12);
        const newHashedPassword = await bcrypt.hash(this.password, salt);

        if (!this.isNew) {
            // Check the new password against the password history
            const passwordIsNotUnique = await this.isPasswordUnique(this.password);
            if (!passwordIsNotUnique) {
                return next(new Error('Cannot use one of the last 5 passwords.'));
            }

            // Add the current hash to the history
            this.passwordHistory.unshift({ passwordHash: this.password });

            // Ensure only the last 5 passwords are kept
            this.passwordHistory = this.passwordHistory.slice(0, 2);
        }

        // Update the password to the new hashed password
        this.password = newHashedPassword;
    }
    next();
});

userSchema.methods.isPasswordUnique = async function (newPassword) {
    const matchPromises = this.passwordHistory.map(
        (historyEntry) => bcrypt.compare(newPassword, historyEntry.passwordHash)
    );

    const matchResults = await Promise.all(matchPromises);
    return !matchResults.includes(true);
};



const User = mongoose.model('User', userSchema);


export default User;

