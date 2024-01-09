import React from 'react';
import { useSelector } from 'react-redux';
import { NavLink, Outlet } from 'react-router-dom';
import '../styles/unauthorized.css';

const AdminRoute = () => {
    const { logged } = useSelector((state) => state.auth);
    const { role, admin } = useSelector((state) => state.user);

    if (!logged || !admin) {
        return (
            <div className="unauthorized">
                <h1 className="block">Admin Access Denied</h1>
                <span>
                    <NavLink to="/">Go home</NavLink>
                </span>
            </div>
        );
    }
    return <Outlet />;
};

export default AdminRoute;
