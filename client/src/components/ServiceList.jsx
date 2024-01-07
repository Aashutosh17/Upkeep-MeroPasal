import React, { useState, useEffect } from 'react';
import axios from 'axios';
import '../App.css';
import { useQuery } from '@tanstack/react-query';
import { API } from '../store';
import Spinner from './Spinner';
import { Link } from 'react-router-dom';

const ServiceList = () => {
    // const [products, setProducts] = useState([]);

    const {
        data: products,
        isError,
        error,
        isLoading,
        refetch,
    } = useQuery(['services'], () => axios.get(`${API}/service`));

    console.log(products);

    if (isLoading) {
        return <Spinner />;
    }

    console.log(products);

    return (
        <div className="min-h-screen bg-gray-100">
            <div className="max-w-7xl mx-auto py-7 sm:px-6 lg:px-8">
                <h1 className="text-6xl  mt-16 font-bold text-center text-green-600">
                    Service List
                </h1>
            </div>
            {/* Service List */}
            <div className="max-w-7xl mx-auto sm:px-6 lg:px-8">
                <div className="flex flex-wrap -mx-4">
                    {products?.data?.length > 0 ? (
                        products?.data?.map((product) => (
                            <Link
                                key={product._id}
                                className="w-full sm:w-1/2 lg:w-1/3 xl:w-1/4 p-4"
                                to={`/service/${product._id}`}
                            >
                                <div className="bg-white rounded-sm shadow-md overflow-hidden">
                                    <img
                                        src={product.image[0]}
                                        alt={product.title}
                                        className="w-full h-48 object-cover hover:scale-[1.1]"
                                    />
                                    <div className="p-4">
                                        <h2 className="text-lg font-semibold text-gray-900">
                                            {product.title}
                                        </h2>
                                        <p className="text-gray-700">
                                            {String(product.desc).substring(
                                                100,
                                                0,
                                            ) + 'see more...'}
                                        </p>
                                        <p className="mt-2 text-gray-900 font-bold">
                                            Rs.{product.price}
                                        </p>
                                    </div>
                                </div>
                            </Link>
                        ))
                    ) : (
                        <div>no products</div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default ServiceList;
