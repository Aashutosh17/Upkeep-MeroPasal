import React from 'react';
import aboutImage from '../assets/images/about.png';
import Footer from '../components/Footer.jsx';
import Navbar from '../components/Navbar.jsx';

const stats = [
    { id: 1, name: 'Total Customers', value: '2000+' },
    { id: 2, name: 'Total Vendors', value: '100+' },
    { id: 3, name: 'Total Services', value: '200+' },
];

const About = () => {
    return (
        <>
            <Navbar />
            <div className="flex bg-white flex-col lg:flex-row items-center justify-center py-24 px-6">
                <div className="lg:w-1/2 lg:mr-10 flex justify-center">
                    <img
                        src={aboutImage}
                        alt="About Us"
                        className="w-full md:max-w-xl rounded-md    "
                    />
                </div>
                <div className="lg:w-1/2 max-w-lg text-center md:text-left">
                    <h2 className="text-4xl text-gray-800 font-bold mb-4">
                        About Us
                    </h2>
                    <p className="text-md text-justify   text-gray-700 mb-8">
                        Our <span className="font-bold text-xl">project</span>{' '}
                        is focused on developing the Mero Pasal platform, which aims
                        to become the leading multi-vendor service provider in
                        Nepal. We are committed to providing customers with
                        high-quality, experienced service providers through our
                        platform. Our main goal is to act as a middleman between
                        service seekers and providers by connecting them through
                        our platform. Our project aims to revolutionize the way
                        services are accessed and provided in Nepal by improving
                        the quality and availability of services through a
                        convenient and easy-to-use platform.
                    </p>
                    <p className="text-md text-justify text-gray-700 mb-8">
                        Our <span className="font-bold text-xl">mission</span>{' '}
                        is to make services accessible to all customers in
                        Nepal. We believe that everyone should have access to
                        high-quality services, and our platform aims to provide
                        just that. By connecting customers with reliable and
                        experienced service providers, we hope to make a
                        positive impact on the service industry in Nepal. We are
                        dedicated to creating a platform that is easy to use,
                        transparent, and reliable, ensuring that customers
                        receive the best possible service.
                    </p>
                    <p className="text-md text-justify text-gray-700 mb-8">
                        Our <span className="font-bold text-xl">vision</span> is
                        to become the go-to platform for customers in Nepal who
                        are seeking quality service providers. We aim to set a
                        new standard for service provision in Nepal by providing
                        a one-stop-shop for all service needs. We envision a
                        future where customers can easily access a wide range of
                        services through our platform, and service providers can
                        connect with potential customers in a seamless and
                        efficient way. Our ultimate goal is to create a platform
                        that benefits both service providers and customers,
                        providing value and convenience to all.
                    </p>
                </div>
            </div>
            <div className="py-9 bg-white">
                <div className="mx-auto max-w-xl">
                    <div className="grid text-center lg:grid-cols-3">
                        {stats.map((stat) => (
                            <div
                                key={stat.id}
                                className="mx-auto flex max-w-xs flex-col gap-y-4"
                            >
                                <div className="text-base leading-7 text-gray-600">
                                    {stat.name}
                                </div>
                                <div className="order-first text-4xl font-bold tracking-tight text-green-600 sm:text-5xl">
                                    {stat.value}
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
            <Footer />
        </>
    );
};

export default About;
