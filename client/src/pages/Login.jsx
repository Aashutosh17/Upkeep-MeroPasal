import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import loginImage from '../assets/images/bgLogin.jpg';
import axios from 'axios';
import { useSelector, useDispatch } from 'react-redux';
import { useForm } from 'react-hook-form';
import Error from '../components/Error';
import Spinner from '../components/Spinner';
import { userLogin } from '../features/auth/authActions';
import { useGetDetailsQuery } from '../app/services/auth/authService';
import { setUser } from '../features/user/userAction';
import { setCredentials } from '../features/user/userSlice';

const Login = () => {
    const { loading, logged, success, userInfo, error } = useSelector(
        (state) => state.auth,
    );
    const { userToken } = useSelector((state) => state.auth);

    // const { data: details, isFetching } = useGetDetailsQuery('userDetails', {
    //     pollingInterval: 900000,
    // });

    const dispatch = useDispatch();
    const navigate = useNavigate();

    const { register, handleSubmit, reset } = useForm();

    useEffect(() => {
        if (logged) navigate('/');
    }, [navigate, logged]);

    const submitForm = (data) => {
        dispatch(userLogin(data));
    };

    return (
        <div className="flex h-screen w-screen bg-black">
            <div
                className="hidden lg:block w-1/2 bg-cover bg-center"
                style={{ backgroundImage: `url(${loginImage})` }}
            ></div>
            <div className="w-full lg:w-1/2 bg-white flex justify-center items-center">
                <form onSubmit={handleSubmit(submitForm)} className="px-8 py-6">
                    <h1 className="text-3xl font-bold mb-1">Welcome Back!</h1>
                    <h4 className="text-md mb-4 font-light">
                        Login into your account
                    </h4>

                    {/* {error && <Error>{error}</Error>} */}
                    <div className="mb-4">
                        <h5 className="text-red-500">{error}</h5>
                        <label
                            htmlFor="email"
                            className="block text-gray-700 font-bold mb-2"
                        >
                            Email/username:
                        </label>
                        <input
                            type="text"
                            id="email"
                            required
                            {...register('emailorusername')}
                            className="w-[420px] border rounded-md border-gray-400 p-2"
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
                            className="w-full border rounded-md border-gray-400 p-2"
                        />
                    </div>

                    <button
                        onClick={handleSubmit}
                        type="submit"
                        className="bg-green-500 text-white font-bold py-2 px-4  focus:outline-none focus:shadow-outline hover:bg-green-600 w-full rounded-md relative"
                    >
                        {loading ? <Spinner /> : 'Login'}
                    </button>

                    <div className="mt-4 text-gray-700 text-center">
                        Did not have an account?
                        <Link
                            to="/signup"
                            className="font-bold text-green-500 hover:text-green-700"
                        >
                            Sign Up
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
                    <div className="mt-4 text-gray-700 text-center">
                        <Link
                            to="/forget-password"
                            className="font-bold text-red-500 hover:text-green-700"
                        >
                            Forget Password
                        </Link>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default Login;
