import React from 'react';
import { Link } from 'react-router-dom';

const ActivationSuccess = () => {
    return (
        <div className="flex flex-col items-center justify-center min-h-screen ">
            <div className="w-full max-w-md">
                <h2 className="text-4xl font-bold mb-4 text-center text-white">
                    Account Activated
                </h2>
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
