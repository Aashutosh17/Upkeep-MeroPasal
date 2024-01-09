import React from 'react';
import Navbar from '../components/Navbar';
import Hero from '../components/Hero';
import Footer from '../components/Footer';
import Features from '../components/Features.jsx';
import Trust from '../components/Trust';
import FAQ from '../components/FAQ.jsx';

const Landing = () => {
    return (
        <>
            <Navbar />
            <Hero />
            <Features />
            <Trust />
            <FAQ />
            <Footer />
        </>
    );
};

export default Landing;
