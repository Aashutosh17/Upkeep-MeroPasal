import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import SignupImage from '../assets/images/bgSignup.jpg';
import { useDispatch, useSelector } from 'react-redux';
import { useForm } from 'react-hook-form';
import { userRegister } from '../features/auth/authActions';
import Error from '../components/Error';
import Spinner from '../components/Spinner';
import zxcvbn from 'zxcvbn';

const SignupPage = () => {
    const [customError, setCustomError] = useState(null);
    const { loading, userInfo, error, success } = useSelector(
        (state) => state.auth,
    );
    const [info, setInfo] = useState('');
    const [passwordStrength, setPasswordStrength] = useState(null);
    const { register, handleSubmit, watch, reset, resetField } = useForm();
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const password = watch('password');

    useEffect(() => {
        if (password) {
            // Call the zxcvbn function and get the score from the result
            const strengthResult = zxcvbn(password);
            // Update the password strength state with the score
            setPasswordStrength(strengthResult.score);
        }
    }, [password]);


    useEffect(() => {
        // redirect authenticated user to profile screen
        // if (userInfo) navigate('/');
        // redirect user to login page if registration was successful


        if (success)
            setInfo(
                'Please activate your account! Link will be valid for next 30 minutes.',
            );
        reset();
        resetField();
    }, [navigate, userInfo, success]);

    const submitForm = (data) => {
        if (data.password !== data.confirmPassword) {
            setCustomError('Password mismatch');
            return;
        }
        // transform email string to lowercase to avoid case sensitivity issues in login
        data.email = data.email.toLowerCase();
        dispatch(userRegister(data));
    };

    const renderPasswordStrengthIndicator = () => {
        let strengthMessage;
        switch (passwordStrength) {
            case 0:
                strengthMessage = 'Very weak';
                break;
            case 1:
                strengthMessage = 'Weak';
                break;
            case 2:
                strengthMessage = 'Fair';
                break;
            case 3:
                strengthMessage = 'Good';
                break;
            case 4:
                strengthMessage = 'Strong';
                break;
            default:
                strengthMessage = 'Enter password';
        }

        return <div className="password-strength-message">{strengthMessage}</div>;
    };


    return (
        <div className="flex h-screen w-screen bg-black">
            <div
                className="hidden lg:block w-1/2 bg-cover bg-center"
                style={{ backgroundImage: `url(${SignupImage})` }}
            ></div>
            <div className="w-full lg:w-1/2 bg-white flex justify-center items-center">
                <form onSubmit={handleSubmit(submitForm)} className="px-8 py-6">
                    {error && <Error>{error}</Error>}
                    {customError && <Error>{customError}</Error>}
                    {info && <span>{info}</span>}
                    <h1 className="text-3xl font-bold mb-1">Welcome!</h1>
                    <h4 className="text-md mb-4 font-light">
                        Let&apos;s create your account
                    </h4>
                    <div className="mb-4">
                        <label
                            htmlFor="fullName"
                            className="block text-gray-700 font-bold mb-2"
                        >
                            Full Name:
                        </label>
                        <input
                            type="text"
                            id="fullName"
                            {...register('fullName')}
                            required
                            name="fullName"
                            className="w-full rounded-md border border-gray-400 p-2"
                        />
                    </div>
                    <div className="mb-4">
                        <label
                            htmlFor="username"
                            className="block text-gray-700 font-bold mb-2"
                        >
                            Username:
                        </label>
                        <input
                            type="text"
                            id="username"
                            name="username"
                            {...register('username')}
                            required
                            className="w-full  rounded-md border border-gray-400 p-2"
                        />
                    </div>

                    <div className="mb-4">
                        <label
                            htmlFor="email"
                            className="block text-gray-700 font-bold mb-2"
                        >
                            Email:
                        </label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            {...register('email')}
                            required
                            className="w-[420px] rounded-md border border-gray-400 p-2"
                        />
                    </div>
                    <div className="mb-4">
                        <label
                            htmlFor="address"
                            className="block text-gray-700 font-bold mb-2"
                        >
                            Address:
                        </label>
                        <input
                            type="address"
                            id="address"
                            name="address"
                            {...register('address')}
                            required
                            className="w-[420px] rounded-md border border-gray-400 p-2"
                        />
                    </div>



                    <div className="mb-4">
                        <label
                            htmlFor="password"
                            className="block text-gray-700 font-bold mb-2"
                        >
                            Password:
                        </label>
                        <input
                            type="password"
                            id="password"
                            {...register('password')}
                            required
                            name="password"
                            className="w-full rounded-md border border-gray-400 p-2"
                        />
                        {password && renderPasswordStrengthIndicator()} {/* Conditionally render the password strength indicator */}
                    </div>



                    <div className="mb-4">
                        <label
                            htmlFor="confirmPassword"
                            className="block text-gray-700 font-bold mb-2"
                        >
                            Confirm Password:
                        </label>
                        <input
                            type="password"
                            id="confirmPassword"
                            name="confirmPassword"
                            {...register('confirmPassword')}
                            required
                            className="w-full rounded-md border border-gray-400 p-2"
                        />
                    </div>

                    <button
                        disabled={loading}
                        type="submit"
                        className="bg-green-500 text-white font-bold py-2 px-4  focus:outline-none focus:shadow-outline hover:bg-green-600 w-full relative rounded-md"
                    >
                        {loading ? <Spinner /> : 'Sign Up'}
                    </button>
                    <div className="mt-4 text-gray-700 text-center">
                        Already have an account?
                        <Link
                            to="/login"
                            className="font-bold text-green-500 hover:text-green-700"
                        >
                            Log in
                        </Link>
                    </div>
                    <div className="mt-4 text-gray-700 text-center">
                        <Link
                            to="/"
                            className="font-bold text-green-500 hover:text-green-700"
                        >
                            Go Back to Home
                        </Link>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default SignupPage;
