import React from 'react';
import Typed from 'react-typed';

const Hero = () => {
    return (
        <div className="text-white">
            <div className="max-w-[800px] mt-[-96px] w-full h-screen mx-auto text-center flex flex-col justify-center">
                <p className="text-[#00df9a] font-bold p-2">
                    FROM TRUSTED VENDORS
                </p>
                <h1 className="md:text-7xl sm:text-6xl text-4xl font-bold md:py-6">
                    Hassle Free Products
                </h1>
                <div className="flex justify-center items-center">
                    <p className="md:text-5xl sm:text-4xl text-xl font-bold py-4">
                        Connect, collaborate,
                    </p>
                    <Typed
                        className="md:text-5xl sm:text-4xl text-xl font-bold md:pl-4 pl-2"
                        strings={['streamline', 'B2C', 'Services']}
                        typeSpeed={120}
                        backSpeed={140}
                        loop
                    />
                </div>
                <p className="md:text-2xl text-xl font-bold text-gray-500">
                    Your one-stop-shop for all your products needs
                </p>
                <button className="bg-[#00df9a] w-[200px] rounded-md font-medium my-6 mx-auto py-3 text-black">
                    Get started for free
                </button>
            </div>
        </div>
    );
};

export default Hero;
