import React from 'react';
import { useSelector } from 'react-redux';
import { NavLink, Outlet } from 'react-router-dom';
import '../styles/unauthorized.css';

const VendorProtected = () => {
    const { logged } = useSelector((state) => state.auth);
    const { role, vendor } = useSelector((state) => state.user);

    if (!logged || !vendor) {
        return (
            <div className="unauthorized">
                <h1 className="block">Vendor Access Denied</h1>
                <span>
                    <NavLink to="/">Go home</NavLink>
                </span>
            </div>
        );
    }
    return <Outlet />;
};

export default VendorProtected;
