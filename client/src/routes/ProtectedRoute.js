import React from 'react';
import { useSelector } from 'react-redux';
import { NavLink, Outlet } from 'react-router-dom';
import '../styles/unauthorized.css';

const ProtectedRoute = () => {
    const { logged } = useSelector((state) => state.auth);

    if (!logged) {
        return (
            <div className="unauthorized">
                <h1 className="block">Unauthorized</h1>
                <span>
                    <NavLink to="/login">Login</NavLink> to gain accesss
                </span>
            </div>
        );
    }
    return <Outlet />;
};

export default ProtectedRoute;
