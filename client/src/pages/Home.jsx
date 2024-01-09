import React from 'react';
import HomeHero from '../components/HomeHero.jsx';
import Navbar from '../components/Navbar.jsx';
import Footer from '../components/Footer';
import ServiceList from '../components/ServiceList.jsx';
import axios from 'axios';

const Home = () => {
    return (
        <>
            <Navbar />
            <HomeHero />
            <ServiceList />
            <Footer />
        </>
    );
};

export default Home;
