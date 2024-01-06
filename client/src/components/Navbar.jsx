import React, { useState } from 'react';
import { AiOutlineClose, AiOutlineMenu } from 'react-icons/ai';
import { Link, useNavigate } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import { logout } from '../features/auth/authSlice';
import { removeCredentials } from '../features/user/userSlice';

const Navbar = () => {
    const { loading, logged } = useSelector((state) => state.auth);
    const { admin, vendor } = useSelector((state) => state.user);
    const [nav, setNav] = useState(false);
    const navigate = useNavigate();
    const dispatch = useDispatch();

    const handleNav = () => {
        setNav(!nav);
    };

    const handleLogout = () => {
        dispatch(removeCredentials());
        dispatch(logout());
        navigate('/');
    };

    return (
        <div className="flex justify-between items-center h-24 max-w-[1240px] mx-auto px-4 text-white">
            <Link to="/" className="w-full text-3xl font-bold text-[#0be9b1]">
                Mero Pasal
            </Link>
            <ul className="hidden md:flex">
                <Link to="/Home" className="p-4">
                    Home
                </Link>
                <Link to="/Home" className="p-4">
                    Service
                </Link>
                <Link to="/help" className="p-4">
                    Help
                </Link>
                <Link to="/about" className="p-4">
                    About
                </Link>
                {logged && (
                    <Link to={'/edit-profile'} className="p-4">
                        Profile
                    </Link>
                )}

                {admin === true && logged === true && (
                    <Link to="/admin" className="p-4">
                        Admin
                    </Link>
                )}
                {vendor === true && logged === true && (
                    <Link to="/vendor" className="p-4">
                        Vendor
                    </Link>
                )}

                {vendor === false && admin === false && logged === true && (
                    <Link to="/request/vendor" className="p-4">
                        Join
                    </Link>
                )}

                {logged ? (
                    <>
                        <button
                            onClick={handleLogout}
                            className="p-4 text-center font-medium rounded-md w-24 px-3 text-black bg-[#00df9a]"
                            style={{
                                height: '40px',
                                paddingTop: '9px',
                                marginTop: '6px',
                            }}
                        >
                            Logout
                        </button>
                    </>
                ) : (
                    <>
                        <Link
                            to="/signup"
                            className="p-4 text-center font-medium rounded-md w-24 px-3 text-black bg-[#00df9a] mr-5"
                            style={{
                                height: '40px',
                                paddingTop: '9px',
                                marginTop: '6px',
                            }}
                        >
                            SignUp
                        </Link>
                        <Link
                            to="/login"
                            className="p-4 text-center font-medium rounded-md w-24 px-3 text-black bg-[#00df9a]"
                            style={{
                                height: '40px',
                                paddingTop: '9px',
                                marginTop: '6px',
                            }}
                        >
                            Login
                        </Link>
                    </>
                )}
            </ul>
            <div onClick={handleNav} className="block md:hidden ">
                {nav ? (
                    <AiOutlineClose size={20} />
                ) : (
                    <AiOutlineMenu size={20} />
                )}
            </div>
            <ul
                className={
                    nav
                        ? 'fixed left-0 top-0 w-[60%] h-full border-r border-r-gray-900 bg-[#000300] ease-in-out duration-500'
                        : 'ease-in-out duration-500 fixed left-[-100%]'
                }
            >
                <h1 className="w-full text-3xl font-bold text-[#00df9a] m-4">
                    Mero Pasal
                </h1>
                <li className="p-4 border-b border-gray-600">Home</li>
                <li className="p-4 border-b border-gray-600">Services</li>
                <li className="p-4 border-b border-gray-600">Help</li>
                <li className="p-4 border-b border-gray-600">About</li>
                <li className="p-4">Become a vendor</li>
            </ul>
        </div>
    );
};

export default Navbar;
