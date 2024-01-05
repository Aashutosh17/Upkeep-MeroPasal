import React, { useEffect } from 'react';
import { Routes, Route, useNavigate } from 'react-router-dom';
import Landing from './pages/Landing.jsx';
import Signup from './pages/Signup';
import Login from './pages/Login';
import Home from './pages/Home.jsx';
import Contact from './components/Contact.jsx';
import About from './pages/About.jsx';
import SingleService from './components/SingleService.jsx';
import OrderConfirm from './components/OrderConfirm';
import Layout from '../src/components/Admin/components/shared/Layout.jsx';
import Dashboard from './components/Admin/pages/Dashboard.jsx';
import TotalVendor from './components/Admin/pages/TotalVendor.jsx';
import TotalCustomer from './components/Admin/pages/TotalCustomer';
import Approvals from './components/Admin/pages/TotalCustomer';
import AdminLogin from './components/Admin/pages/AdminLogin';
import CheckoutForm from './components/CheckoutForm.jsx';
import ActivationSuccess from './pages/ActivationSuccess.jsx';
import ForgetPassword from './pages/ForgetPassword.jsx';
import Vendor from './pages/Vendor.jsx';
import Activate from './components/Auth/Activate.jsx';
// import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import { getUser } from './features/user/userAction.js';
import { useGetDetailsQuery } from './app/services/auth/authService.js';
import { setCredentials } from './features/user/userSlice.js';
import ProtectedRoute from './routes/ProtectedRoute.js';
import VendorApproval from './components/Admin/pages/VendorApproval';
import CreateCategory from './components/Admin/pages/CreateCategory';
import AdminRoute from './routes/AdminRoute.js';
import VendorLayout from './components/Vendor/components/shared/VendorLayout.jsx';
import VendorDashboard from './components/Vendor/pages/VendorDashboard.jsx';
import UploadService from './components/Vendor/pages/AddService.jsx';
import AddService from './components/Vendor/pages/AddService.jsx';
import TotalOrders from './components/Vendor/pages/TotalOrders.jsx';
import Chat from './components/Vendor/pages/Chat.jsx';
import VendorProtected from './routes/VendorProtected';
import Reset from './pages/Reset.jsx';
import Service from './components/Admin/pages/Service.jsx';
import EditProfile from './components/EditProfile.jsx';

const App = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();

    const { email, username, vendorAccess, admin, role } = useSelector(
        (state) => state.user,
    );
    const { loading, logged, userToken, userInfo, error } = useSelector(
        (state) => state.auth,
    );

    const { data, isFetching, refetch } = useGetDetailsQuery('userDetails', {
        pollingInterval: 900000, // 15 minutes
    });

    useEffect(() => {
        if (data && !isFetching) {
            refetch();
            dispatch(setCredentials(data));
        }
    }, [data, dispatch, userToken]);


    return (
        <>
            <div>
                <Routes>
                    <Route exact path="/" element={<Landing />}></Route>
                    <Route path="/home" element={<Home />} />
                    <Route path="/signup" element={<Signup />} />
                    <Route path="/login" element={<Login />} />
                    <Route path="/home" element={<Home />} />
                    <Route element={<ProtectedRoute />}>
                        <Route path="/help" element={<Contact />} />
                    </Route>
                    <Route path="/about" element={<About />} />
                    <Route
                        path="/forget-password"
                        element={<ForgetPassword />}
                    />
                    <Route
                        path="/activation-success"
                        element={<ActivationSuccess />}
                    />
                    <Route path="/service/:id" element={<SingleService />} />
                    <Route element={<ProtectedRoute />}>
                        <Route
                            path="/edit-profile"
                            element={<EditProfile refetch={refetch} />}
                        />
                        <Route
                            path="/order-confirm"
                            element={<OrderConfirm />}
                        />
                        <Route
                            path="/checkout/:id"
                            element={<CheckoutForm />}
                        />
                        <Route path="/request/vendor" element={<Vendor />} />
                    </Route>

                    {/* Admin */}

                    {/* <Route path="admin-login" element={<AdminLogin />} /> */}
                    <Route element={<AdminRoute />}>
                        <Route path="/admin" element={<Layout />}>
                            <Route index element={<Dashboard />} />
                            <Route
                                path="totalcustomer"
                                element={<TotalCustomer />}
                            />
                            <Route
                                path="totalvendor"
                                element={<TotalVendor />}
                            />
                            <Route
                                path="vendor-approval"
                                element={<VendorApproval />}
                            />
                            <Route
                                path="create-category"
                                element={<CreateCategory />}
                            />
                            <Route path="services" element={<Service />} />
                        </Route>
                    </Route>
                    {/* Vendor */}
                    <Route element={<VendorProtected />}>
                        <Route path="/vendor" element={<VendorLayout />}>
                            <Route index element={<VendorDashboard />} />
                            <Route path="addservice" element={<AddService />} />
                            <Route
                                path="total-orders"
                                element={<TotalOrders />}
                            />
                            <Route path="chat" element={<Chat />} />
                        </Route>
                    </Route>

                    <Route path="/auth/activate/:id" element={<Activate />} />
                    <Route path="/auth/reset/:token" element={<Reset />} />
                    {/* <Route element={Error} /> */}
                </Routes>
            </div>
        </>
    );
};

export default App;
