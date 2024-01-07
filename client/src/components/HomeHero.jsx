import React from 'react';
import Typed from 'react-typed';

const HomeHero = () => {
    return (
        <>
            <div className="text-white">
                <div className="max-w-[800px] mt-[-97px] w-full h-screen mx-auto text-center flex flex-col justify-center">
                    <p className="text-[#00df9a] font-bold p-2">
                        Explore the Services
                    </p>
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
                        Your one-stop-shop for all your service needs
                    </p>
                    <div className="max-w-md mx-auto mt-8 mr-[255px]">
                        <form className="flex">
                            <input
                                className="rounded-l-lg p-4 border-t mr-0 border-b border-l outline-none text-gray-800 border-gray-200 bg-white"
                                placeholder="Kathmandu"
                            />
                            <input
                                className="rounded-r-lg p-4 border-t mr-0 border-b outline-none border-r text-gray-800 border-gray-200 bg-white"
                                placeholder="Search for services"
                            />
                            <button className=" mx-2.5 px-10 rounded-lg bg-[#00df9a] text-black font-bold p-4 uppercase border-gray-200 border-t border-b  border-l border-r">
                                Search
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </>
    );
};

export default HomeHero;
