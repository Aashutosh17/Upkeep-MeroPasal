import React, { useEffect } from 'react';
import Navbar from './Navbar.jsx';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import Spinner from './Spinner.jsx';
import axios from 'axios';
import { API } from '../store.js';
import Footer from './Footer.jsx';
import { Link } from 'react-router-dom';

const SingleService = () => {
    const { id } = useParams();

    // useEffect(() => {
    //     refetch();
    // }, [id]);

    const { data, isFetching } = useQuery(['singleservice'], async () => {
        const res = await axios.get(`${API}/service/single?id=${id}`);
        return res.data;
    });

    if (isFetching) {
        return <Spinner />;
    }

    return (
        <>
            <Navbar />
            <section className="text-gray-600 bg-white dark:bg-gray-900 body-font overflow-hidden">
                <div className="container px-5 py-24 mx-auto">
                    <div className="lg:w-4/5 mx-auto flex flex-wrap">
                        <img
                            alt="Plumber Service"
                            className="lg:w-1/2 w-full lg:h-96 h-64 object-contain object-center rounded "
                            src={data?.image[0]}
                        />
                        <div className="lg:w-1/2 w-full lg:pl-10 lg:py-6 mt-6 lg:mt-0">
                            <h2 className="text-sm title-font text-gray-500 dark:text-gray-300 tracking-widest">
                                <img
                                    src={data?.user?.profile}
                                    alt={data.name}
                                    className="w-4 h-4 rounded-full inline-block mr-5"
                                />
                                {data?.user?.name}
                            </h2>
                            <h1 className="text-gray-900 dark:text-white text-3xl title-font font-medium mb-1">
                                {data.title}
                            </h1>
                            <div className="flex mb-4">
                                <span className="flex items-center">
                                    <svg
                                        fill="currentColor"
                                        stroke="currentColor"
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth="2"
                                        className="w-4 h-4 text-green-500"
                                        viewBox="0 0 24 24"
                                    >
                                        <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"></path>
                                    </svg>
                                    <svg
                                        fill="currentColor"
                                        stroke="currentColor"
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth="2"
                                        className="w-4 h-4 text-green-500"
                                        viewBox="0 0 24 24"
                                    >
                                        <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"></path>
                                    </svg>
                                    <svg
                                        fill="currentColor"
                                        stroke="currentColor"
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth="2"
                                        className="w-4 h-4 text-green-500"
                                        viewBox="0 0 24 24"
                                    >
                                        <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"></path>
                                    </svg>
                                    <svg
                                        fill="currentColor"
                                        stroke="currentColor"
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth="2"
                                        className="w-4 h-4 text-green-500"
                                        viewBox="0 0 24 24"
                                    >
                                        <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"></path>
                                    </svg>
                                    <svg
                                        fill="none"
                                        stroke="currentColor"
                                        strokeLinecap="round"
                                        strokeLinejoin="round"
                                        strokeWidth="2"
                                        className="w-4 h-4 text-green-500"
                                        viewBox="0 0 24 24"
                                    >
                                        <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"></path>
                                    </svg>
                                    <span className="text-gray-600 dark:text-gray-300 ml-3">
                                        {data?.reviews} Reviews
                                    </span>
                                </span>
                            </div>
                            <p className="leading-relaxed dark:text-gray-300">
                                {data.desc}
                            </p>

                            <div className="flex ">
                                <span className="title-font font-medium text-2xl text-gray-900 dark:text-white">
                                    Rs. {data.price}
                                </span>
                            </div>
                            <Link
                                to={`/checkout/${data._id}`}
                                className="ml-auto  mt-4 rounded-md bg-green-600 px-3.5 py-1.5 text-base font-semibold leading-7 text-white hover:bg-red-500"
                            >
                                Book Now
                            </Link>
                        </div>
                    </div>
                </div>
            </section>
            <Footer />
        </>
    );
};

export default SingleService;
