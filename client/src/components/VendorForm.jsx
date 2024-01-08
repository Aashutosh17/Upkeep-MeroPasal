import React, { useState } from 'react';
import Navbar from '../components/Navbar.jsx';
import Footer from '../components/Footer.jsx';
import { useForm } from 'react-hook-form';
import { toast } from 'react-toastify';
import axios from 'axios';
import { API } from '../store.js';
import { useSelector } from 'react-redux';

const VendorRequestForm = () => {
    const { register, handleSubmit, reset } = useForm();
    const { userToken } = useSelector((state) => state.auth);

    const submit = async (data) => {
        // send form data to server or do validation
        console.log({ ...data });
        try {
            const response = await axios.patch(
                `${API}/user/update`,
                { ...data },
                {
                    headers: {
                        'Content-Type': 'application/json',
                        Authorization: `Bearer ${userToken}`,
                    },
                },
            );

            if (response.status == 200) {
                // reset();
                const data = await axios.post(
                    `${API}/user/vendor`,
                    {},
                    {
                        headers: {
                            'Content-Type': 'application/json',
                            Authorization: `Bearer ${userToken}`,
                        },
                    },
                );
                if (data.status === 200) {
                    reset();
                }

                toast.info(data?.data?.msg);
                // queryClient.invalidateQueries('services');
            }
        } catch (error) {
            console.log(error);
            toast.error(error.response.data.msg);
        }
    };

    return (
        <>
            <Navbar />
            <div className="flex min-h-screen">
                <div className="w-full  bg-white flex justify-center items-center">
                    <form onSubmit={handleSubmit(submit)} className="px-8 py-6">
                        <h1 className="text-3xl font-bold mb-1">
                            Become Professional Vendor
                        </h1>
                        <h4 className="text-md mb-2 font-light">
                            Request a Vendor Account
                        </h4>
                        <div className="mb-4">
                            <label
                                htmlFor="name"
                                className="block text-gray-700 font-bold mb-2"
                            >
                                {' '}
                                Full Name
                            </label>
                            <input
                                type="name"
                                id="name"
                                required
                                name="name"
                                {...register('name')}
                                className="w-[420px] border rounded-md border-gray-400 p-2"
                            />
                        </div>
                        <div className="mb-4">
                            <label
                                htmlFor="email"
                                className="block text-gray-700 font-bold mb-2"
                            >
                                Business Email
                            </label>
                            <input
                                type="email"
                                id="email"
                                required
                                name="email"
                                {...register('business_email')}
                                className="w-full border rounded-md border-gray-400 p-2"
                            />
                        </div>
                        <div className="mb-4">
                            <label
                                htmlFor="phone"
                                className="block text-gray-700 font-bold mb-2"
                            >
                                Phone Number
                            </label>
                            <input
                                type="text"
                                id="phone"
                                required
                                {...register('phone')}
                                className="w-full border rounded-md border-gray-400 p-2"
                            />
                        </div>
                        {/* <div className="mb-4">
                            <label
                                htmlFor="citizenship"
                                className="block text-gray-700 font-bold mb-2"
                            >
                                Citizenship
                            </label>
                            <input
                                type="file"
                                id="citizenship"
                                name="citizenship"
                                accept=".pdf,.jpeg,.jpg,.png"
                                className="w-full border rounded-md border-gray-400 p-2"
                            />
                        </div> */}
                        <div className="mb-4">
                            <label
                                htmlFor="business_name"
                                className="block text-gray-700 font-bold mb-2"
                            >
                                Business Name
                            </label>
                            <input
                                type="text"
                                required
                                id="business_name"
                                name="business_name"
                                {...register('business_name')}
                                className="w-[420px] border rounded-md border-gray-400 p-2"
                            />
                        </div>

                        <div className="mb-4">
                            <label
                                htmlFor="business_address"
                                className="block text-gray-700 font-bold mb-2"
                            >
                                Business Address
                            </label>
                            <input
                                type="text"
                                {...register('business_address')}
                                id="business_address"
                                required
                                name="business_address"
                                className="w-full border rounded-md border-gray-400 p-2"
                            />
                        </div>
                        <div className="mb-4">
                            <label
                                htmlFor="panno"
                                className="block text-gray-700 font-bold mb-2"
                            >
                                PAN Number
                            </label>
                            <input
                                type="text"
                                {...register('panno')}
                                id="panno"
                                name="panno"
                                required
                                className="w-full border rounded-md border-gray-400 p-2"
                            />
                        </div>
                        <button
                            type="submit"
                            className="bg-green-500 text-white font-bold py-2 px-4  focus:outline-none focus:shadow-outline hover:bg-green-600 w-full rounded-md"
                        >
                            Request Vendor
                        </button>
                    </form>
                </div>
            </div>
            <Footer />
        </>
    );
};

export default VendorRequestForm;
