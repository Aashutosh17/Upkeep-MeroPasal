import React, { useEffect, useState } from 'react';
import { useForm } from 'react-hook-form';
import { useSelector } from 'react-redux';
import {
    QueryClientProvider,
    useQuery,
    useQueryClient,
} from '@tanstack/react-query';
import axios from 'axios';
import { API } from '../store';
import Spinner from './Spinner';
import { toast } from 'react-toastify';
import { useNavigate } from 'react-router-dom';
import Navbar from './Navbar';
import Footer from './Footer';

const EditProfile = () => {
    const { id } = useSelector((state) => state.user);
    const { userToken } = useSelector((state) => state.auth);
    const { register, handleSubmit } = useForm();
    const queryClient = useQueryClient();
    const navigate = useNavigate();

    const {
        data: updatedUser,
        isLoading,
        error,
    } = useQuery(['profile'], () =>
        axios.get(`${API}/auth/user`, {
            headers: { Authorization: `Bearer ${userToken}` },
        }),
    );
    // console.log(id, userToken, updatedUser);

    // console.log(error);

    const onSubmit = async (data) => {
        try {
            const res = await axios.patch(
                `${API}/user/update`,
                { ...data },
                { headers: { Authorization: `Bearer ${userToken}` } },
            );
            console.log(res);

            if (res.status == 200) {
                queryClient.invalidateQueries('profile');

                navigate('/');
            }
            // Your update user function here
        } catch (error) {
            console.log(error);
        }
    };

    const handleImage = async (e) => {
        try {
            const formdata = new FormData();

            formdata.append('images', e.target.files[0]);
            const res = await axios.post(`${API}/user/profile`, formdata, {
                headers: { Authorization: `Bearer ${userToken}` },
            });
            queryClient.invalidateQueries('profile');
        } catch (error) {
            console.log(error);
            toast.error(error);
        }
    };

    return (
        <>
            <Navbar />
            {!isLoading && (
                <div className="flex my-24 justify-center items-center h-fit">
                    <div className="text-white w-full max-w-md rounded-lg shadow-md overflow-hidden">
                        <div className="px-6 py-4">
                            <div className="flex justify-center">
                                <label htmlFor="avatar">
                                    <img
                                        className="w-32 h-32 rounded-full border-2 object-cover cursor-pointer"
                                        src={updatedUser?.data?.profile}
                                        alt="Avatar"
                                    />
                                </label>
                                <input
                                    className="hidden"
                                    type="file"
                                    id="avatar"
                                    name="profile"
                                    accept="image/png, image/jpeg"
                                    onChange={handleImage}
                                />
                            </div>
                            <form
                                className="mt-6"
                                onSubmit={handleSubmit(onSubmit)}
                            >
                                <div>
                                    <label className="block  font-semibold mb-2">
                                        Name
                                    </label>
                                    <input
                                        className="w-full text-black border  p-2 rounded-lg"
                                        type="text"
                                        name="name"
                                        defaultValue={updatedUser?.data?.name}
                                        {...register('name')}
                                    />
                                </div>

                                <div className="mt-4">
                                    <label className="block  font-semibold mb-2">
                                        Pan No
                                    </label>
                                    <input
                                        className="w-full text-black border  p-2 rounded-lg"
                                        type="text"
                                        name="panno"
                                        defaultValue={updatedUser?.data?.panno}
                                        {...register('panno')}
                                    />
                                </div>
                                <div className="mt-4">
                                    <label className="block  font-semibold mb-2">
                                        Phone Number
                                    </label>
                                    <input
                                        className="w-full text-black border  p-2 rounded-lg"
                                        type="text"
                                        name="phone"
                                        defaultValue={updatedUser?.data?.phone}
                                        {...register('phone')}
                                    />
                                </div>
                                <div className="mt-4">
                                    <label className="block  font-semibold mb-2">
                                        Business Name
                                    </label>
                                    <input
                                        className="w-full text-black border  p-2 rounded-lg"
                                        type="text"
                                        name="business_name"
                                        // value={updatedUser?.data?.business_name}
                                        defaultValue={
                                            updatedUser?.data?.business_name
                                        }
                                        {...register('business_name')}
                                    />
                                </div>
                                <div className="mt-4">
                                    <label className="block  font-semibold mb-2">
                                        Business Address
                                    </label>
                                    <input
                                        className="w-full text-black border  p-2 rounded-lg"
                                        type="text"
                                        name="business_address"
                                        defaultValue={
                                            updatedUser?.data?.business_address
                                        }
                                        {...register('business_address')}
                                    />
                                </div>
                                <div className="mt-4">
                                    <button
                                        type="submit"
                                        className="w-full  bg-blue-500 text-white p-2 rounded-lg hover:bg-blue-600"
                                    >
                                        Edit Profile
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            )}
            <Footer />
        </>
    );
};

export default EditProfile;
