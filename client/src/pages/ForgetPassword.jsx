import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { API } from '../store';
import { useDispatch, useSelector } from 'react-redux';
import { forgetPassword } from '../features/auth/authActions';
import Error from '../components/Error';
import Spinner from '../components/Spinner';

const ForgetPassword = () => {
    const { error, loading, data: dataa } = useSelector((state) => state.auth);
    const { register, handleSubmit, reset } = useForm();
    const dispatch = useDispatch();

    const submitHandler = async (data) => {
        dispatch(forgetPassword({ email: data.email }));
        reset();
    };

    return (
        <div className="flex flex-col items-center justify-center min-h-screen">
            <div className="w-full max-w-md">
                <h2 className="text-4xl font-bold mb-4 text-green-500">
                    Forget Password
                </h2>
                <form onSubmit={handleSubmit(submitHandler)}>
                    {error && <Error>{error}</Error>}
                    {dataa?.msg && (
                        <p className="text-white mb-6">{dataa?.msg}</p>
                    )}
                    <div className="mb-4">
                        <label
                            className="block font-bold mb-2 text-white"
                            htmlFor="email"
                        >
                            Enter Email Address
                        </label>
                        <input
                            className="w-full border-gray-300 p-3 rounded-lg outline-none"
                            type="email"
                            id="email"
                            placeholder="Enter registered email"
                            name="email"
                            {...register('email')}
                            required
                        />
                    </div>
                    <div className="flex justify-center">
                        <button className="bg-green-500 text-white font-bold py-2 px-4 rounded-md hover:bg-red-700 focus:outline-none focus:shadow-outline relative">
                            {loading ? <Spinner /> : 'Send Link'}
                        </button>
                    </div>
                </form>
                <p className="text-center mt-4 text-white">
                    Remembered your password?{' '}
                    <Link to="/login" className="text-green-500">
                        Log in
                    </Link>
                </p>
            </div>
        </div>
    );
};

export default ForgetPassword;
