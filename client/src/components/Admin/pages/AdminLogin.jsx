import React from 'react';

const AdminLogin = () => {
    return (
        <div className="flex min-h-screen bg-black">
            <div className="w-full  bg-white flex justify-center items-center">
                <form className="px-8 py-6">
                    <h1 className="text-3xl font-bold mb-1">Welcome Admin!</h1>
                    <h4 className="text-md mb-4 font-light">
                        Login into the system
                    </h4>
                    <div className="mb-4">
                        <label htmlFor="email" className="block text-gray-700 font-bold mb-2">
                            Email:
                        </label>
                        <input
                            type="email"
                            id="email"
                            name="email"
                            className="w-[420px] border rounded-md border-gray-400 p-2"
                        />
                    </div>
                    <div className="mb-4">
                        <label htmlFor="password" className="block text-gray-700 font-bold mb-2">
                            Password:
                        </label>
                        <input
                            type="password"
                            id="password"
                            name="password"
                            className="w-full border rounded-md border-gray-400 p-2"
                        />
                    </div>
                    <button
                        type="submit"
                        className="bg-green-500 text-white font-bold py-2 px-4  focus:outline-none focus:shadow-outline hover:bg-green-600 w-full rounded-md"
                    >
                        Login
                    </button>
                    <div className="mt-4 text-gray-700 text-center">
                        <div>
                            Username: <b>admin</b>
                        </div>

                        <div>
                            Password: <b>admin</b>
                        </div>

                    </div>
                </form>
            </div>
        </div>
    );
};

export default AdminLogin;
