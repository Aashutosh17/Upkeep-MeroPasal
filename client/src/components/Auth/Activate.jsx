import React, { useEffect } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { useSelector, useDispatch } from 'react-redux';
import { activateUser } from '../../features/auth/authActions';
import Spinner from '../Spinner';

const ActivationSuccess = () => {
    const { id } = useParams();

    const { loading, success, error, userInfo } = useSelector(
        (state) => state.auth,
    );
    const dispatch = useDispatch();
    const navigate = useNavigate();

    useEffect(() => {
        dispatch(activateUser({ id }));
        if (success) navigate('/');
    }, [dispatch, id]);

    return (
        <div className="flex flex-col items-center justify-center min-h-screen ">
            <div className="w-full max-w-md">
                <h2 className="text-4xl font-bold mb-4 text-center text-white">
                    {loading ? <Spinner /> : 'Account Activated'}
                </h2>
                <h1 className="text-sm mb-4 text-center text-white">{error}</h1>
                <p className="text-center text-white">
                    Your account has been successfully activated. You can now{' '}
                    <Link to="/login" className="text-green-500 font-medium">
                        log in
                    </Link>{' '}
                    to start using our app.
                </p>
            </div>
        </div>
    );
};

export default ActivationSuccess;
