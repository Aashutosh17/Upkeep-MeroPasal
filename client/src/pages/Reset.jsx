import React, { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { API } from '../store';
import { useDispatch, useSelector } from 'react-redux';
import { forgetPassword, resetPassword } from '../features/auth/authActions';
import Error from '../components/Error';
import Spinner from '../components/Spinner';

const Reset = () => {
    const { error, loading, data: dataa } = useSelector((state) => state.auth);
    const { register, handleSubmit, reset } = useForm();
    const dispatch = useDispatch();
    const [err, setErr] = useState('');
    const { token } = useParams();

    const submitHandler = async (data) => {
        if (data.password !== data.cpassword) {
            return setErr('Password not matched');
        }

        dispatch(resetPassword({ password: data.password, token }));
        reset();
    };

    return (
        <div className="flex flex-col items-center justify-center min-h-screen">
            <div className="w-full max-w-md">
                <h2 className="text-4xl  font-bold mb-10 text-green-500">
                    Reset Your Password
                </h2>
                <form onSubmit={handleSubmit(submitHandler)}>
                    {error && <Error>{error}</Error>}
                    {err && <Error>{err}</Error>}
                    {dataa?.msg && (
                        <p className="text-white mb-6">
                            {dataa?.msg} | Please Login Now
                        </p>
                    )}
                    <div className="mb-4">
                        <label
                            className="block font-bold mb-2 text-white"
                            htmlFor="password"
                        >
                            New Password
                        </label>
                        <input
                            className="w-full border-gray-300 p-3 rounded-lg outline-none"
                            type="password"
                            id="password"
                            placeholder="monkeyponkey"
                            onFocus={(e) => setErr('')}
                            name="password"
                            onChange={(e) => setErr('')}
                            {...register('password')}
                        />
                    </div>
                    <div className="mb-4">
                        <label
                            className="block font-bold mb-2 text-white"
                            htmlFor="password"
                        >
                            Confirm New Password
                        </label>
                        <input
                            className="w-full border-gray-300 p-3 rounded-lg outline-none"
                            type="password"
                            id="password"
                            placeholder="***********"
                            onFocus={(e) => setErr('')}
                            name="password"
                            {...register('cpassword')}
                        />
                    </div>
                    <div className="flex justify-center">
                        <button className="bg-green-600 text-white font-bold py-2 px-4 rounded-md hover:bg-green-400 focus:outline-none focus:shadow-outline relative">
                            {loading ? <Spinner /> : 'Change Password'}
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

export default Reset;
