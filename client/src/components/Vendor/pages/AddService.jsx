import React, { useState } from 'react';
import { API } from '../../../store';
import { useSelector } from 'react-redux';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';
import { useForm } from 'react-hook-form';
import { toast } from 'react-toastify';

const AddService = () => {
    const { register, reset, handleSubmit } = useForm();
    const queryClient = useQueryClient();
    const { userToken } = useSelector((state) => state.auth);

    const onSubmit = async (data) => {
        const formData = new FormData();
        formData.append('title', data.title);
        formData.append('price', data.price);
        formData.append('desc', data.desc);
        // formData.append('category', data.category);

        const selectedFiles = Array.from(data.file);
        // submit the form data to backend API
        selectedFiles.forEach((image) => formData.append('images', image));

        try {
            const response = await axios.post(
                `${API}/service?id=${data.category}`,
                formData,
                {
                    headers: {
                        'Content-Type': 'multipart/form-data',
                        Authorization: `Bearer ${userToken}`,
                    },
                },
            );
            console.log(response);

            if (response.status == 200) {
                reset();
                queryClient.invalidateQueries('services');
            }
            toast(response.data.msg);
        } catch (error) {
            console.log(error);
            toast.error(error.response.data.msg);
        }
    };

    const { data, isLoading, error, refetch } = useQuery(
        ['category'],
        async () => {
            const response = await axios.get(`${API}/admin/category`);
            return response.data;
        },
    );

    return (
        <form
            onSubmit={handleSubmit(onSubmit)}
            className="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4"
        >
            <h1 className="text-center font-bold text-2xl"> Add Service</h1>
            <div className="mb-4">
                <label
                    className="block text-gray-700 font-bold mb-2"
                    htmlFor="name"
                >
                    Name
                </label>
                <input
                    className="appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                    id="name"
                    type="text"
                    placeholder="Service Name"
                    {...register('title')}
                />
            </div>
            <div className="mb-4">
                <label
                    className="block text-gray-700 font-bold mb-2"
                    htmlFor="price"
                >
                    Price
                </label>
                <input
                    className=" appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                    id="price"
                    {...register('price')}
                    type="number"
                    placeholder="Service Price"
                />
            </div>
            <div className="mb-4">
                <label
                    className="block text-gray-700 font-bold mb-2"
                    htmlFor="description"
                >
                    Description
                </label>
                <textarea
                    className="appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                    id="description"
                    {...register('desc')}
                    placeholder="Service Description"
                ></textarea>
            </div>
            {!isLoading && (
                <div className="mb-4">
                    <label
                        className="block text-gray-700 font-bold mb-2"
                        htmlFor="category"
                    >
                        Category
                    </label>
                    <div className="relative">
                        <select
                            className="block appearance-none w-full bg-gray-200 border border-gray-200 text-gray-700 py-2 px-3 pr-8 rounded leading-tight focus:outline-none focus:bg-white focus:border-gray-500"
                            id="category"
                            {...register('category')}
                        >
                            <option value="">Select a category</option>
                            {!isLoading &&
                                data?.map((item, index) => (
                                    <option key={index} value={item._id}>
                                        {item.name}
                                    </option>
                                ))}
                        </select>
                        <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-gray-700">
                            <svg
                                className="fill-current h-4 w-4"
                                xmlns="http://www.w3.org/2000/svg"
                                viewBox="0 0 20 20"
                            >
                                <path
                                    fillRule="evenodd"
                                    d="M9.29289 11.2929C9.68342 11.6834 10.3166 11.6834 10.7071 11.2929L14.7071 7.29289C15.0976 6.90237 15.0976 6.2692 14.7071 5.87868C14.3166 5.48815 13.6834 5.48815 13.2929 5.87868L10 9.17157L6.70711 5.87868C6.31658 5.48815 5.68342 5.48815 5.29289 5.87868C4.90237 6.2692 4.90237 6.90237 5.29289 7.29289L9.29289 11.2929Z"
                                />
                            </svg>
                        </div>
                    </div>
                </div>
            )}
            <div className="mb-4">
                <label
                    className="block text-gray-700 font-bold mb-2"
                    htmlFor="image"
                >
                    Image
                </label>
                <input
                    {...register('file')}
                    className=" appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                    id="image"
                    type="file"
                    multiple
                    accept="image/*"
                />
            </div>
            <div className="flex items-center justify-between">
                <button
                    className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                    type="submit"
                >
                    Add Service
                </button>
            </div>
        </form>
    );
};
export default AddService;
