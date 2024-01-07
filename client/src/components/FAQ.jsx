import React from 'react';
import { Link } from 'react-router-dom';

const FAQ = () => {
    return (
        <section className="max-w-7xl mx-auto mt-10 px-10 md:px-0 py-10 ">
            <div className="px-4 mx-auto sm:px-6 lg:px-8 max-w-7xl">
                <div className="max-w-2xl mx-auto lg:text-center">
                    <h2 className="text-3xl font-bold leading-tight text-white dark:text-white sm:text-4xl lg:text-5xl">
                        Frequently Asked Questions
                    </h2>
                    <p className="max-w-xl lg:mx-auto mt-4 text-base leading-relaxed text-gray-600">
                        Lorem ipsum, dolor sit amet consectetur adipisicing
                        elit. Facere, assumenda
                    </p>
                </div>
                <div className="max-w-3xl mx-auto mt-8 md:mt-16 grid grid-cols-1 md:grid-cols-2 gap-6 ml-[260px]">
                    {Array.from({ length: 4 }).map((_, i) => (
                        <div key={i}>
                            <h2 className="font-semibold text-xl text-white dark:text-white">
                                How do I get started?
                            </h2>
                            <p className="text-sm leading-6 tracking-wide text-gray-500 mt-6">
                                Lorem ipsum dolor sit amet consectetur
                                adipisicing elit. Repellat aliquam adipisci
                                iusto aperiam? Sint asperiores sequi nobis
                                inventore ratione deleniti?
                            </p>
                        </div>
                    ))}
                </div>
                <p className="ml-[400px]  text-gray-600 textbase mt-10">
                    Can&apos;t find what you&apos;re looking for?{' '}
                    <Link
                        to="/help"
                        className="font-medium  text-green-600 hover:underline"
                    >
                        Contact us
                    </Link>
                </p>
            </div>
        </section>
    );
};

export default FAQ;
