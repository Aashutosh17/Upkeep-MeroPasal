import React, { useState } from 'react';
import axios from 'axios';
import { useQuery } from '@tanstack/react-query';
import { useSelector } from 'react-redux';
import { API } from '../../../store';

function Totalcostumer() {
    const { userToken } = useSelector((state) => state.auth);
    // const [users, setUsers] = useState([]);
    const [page, setPage] = useState(1);
    const [size, setSize] = useState(10);

    const { data: users, isLoading } = useQuery(['users'], async () => {
        const response = await axios.get(
            `${API}/user?page=${page}&size=${size}`,
            { headers: { Authorization: `Bearer ${userToken}` } },
        );
        console.log(response);

        return response.data;
    });

    return (
        <div className="flex flex-col h-screen">
            <div className="flex items-center justify-between px-4 py-2 bg-gray-800">
                <h1 className="text-lg font-semibold text-white">
                    Total Customers
                </h1>
                <button
                    className="px-3 py-1 text-sm font-medium text-white bg-blue-600 rounded hover:bg-blue-500"
                    // onClick={fetchUsers}
                >
                    Refresh
                </button>
            </div>
            <div className="flex-grow px-4 py-6 overflow-auto">
                <table className="w-full border-collapse">
                    <thead>
                        <tr>
                            <th className="p-3 font-medium text-left text-gray-800 border border-gray-300">
                                ID
                            </th>
                            <th className="p-3 font-medium text-left text-gray-800 border border-gray-300">
                                Name
                            </th>
                            <th className="p-3 font-medium text-left text-gray-800 border border-gray-300">
                                Username
                            </th>
                            <th className="p-3 font-medium text-left text-gray-800 border border-gray-300">
                                Email
                            </th>
                            <th className="p-3 font-medium text-left text-gray-800 border border-gray-300">
                                PAN
                            </th>
                            <th className="p-3 font-medium text-left text-gray-800 border border-gray-300">
                                Address
                            </th>
                            <th className="p-3 font-medium text-left text-gray-800 border border-gray-300">
                                Phone
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        {users?.map((user, index) => (
                            <tr
                                key={index}
                                className="border-t border-gray-300"
                            >
                                <td className="p-3 text-sm font-medium text-gray-800 border border-gray-300">
                                    {index + 1}
                                </td>
                                <td className="p-3 text-sm font-medium text-gray-800 border border-gray-300">
                                    {user.name}
                                </td>
                                <td className="p-3 text-sm font-medium text-gray-800 border border-gray-300">
                                    <img
                                        src={user.profile}
                                        alt={user.name}
                                        className="w-4 h-4 rounded-full inline-block mr-5"
                                    />
                                    {user.username}
                                </td>
                                <td className="p-3 text-sm font-medium text-gray-800 border border-gray-300">
                                    {user.email}
                                </td>
                                <td className="p-3 text-sm font-medium text-gray-800 border border-gray-300">
                                    {user.panno}
                                </td>
                                <td className="p-3 text-sm font-medium text-gray-800 border border-gray-300">
                                    {user?.address}
                                </td>
                                <td className="p-3 text-sm font-medium text-gray-800 border border-gray-300">
                                    {user.phone}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

export default Totalcostumer;
