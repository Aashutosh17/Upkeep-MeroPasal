import React, { useState } from 'react';
import axios from 'axios';
import { useQuery } from '@tanstack/react-query';
import { API } from '../../../store';
import { useSelector } from 'react-redux';
import { toast } from 'react-toastify';

function VendorApproval() {
    const { userToken } = useSelector((state) => state.auth);

    const [loading, setLoading] = useState(false);

    const {
        data: vendorUsers,
        isLoading,
        refetch,
    } = useQuery(['vendorUsers'], async () => {
        const response = await axios.get(`${API}/admin/pending_vendors`, {
            headers: { Authorization: `Bearer ${userToken}` },
        });
        console.log(response);
        return response.data;
    });

    async function handleApprove(action, id) {
        console.log(userToken);
        console.log(action, id);
        try {
            const res = await axios.patch(
                `${API}/admin/vendor?action=${action}&id=${id}`,
                {},
                {
                    headers: { Authorization: `Bearer ${userToken}` },
                },
            );
            toast.success(res.data.msg);
        } catch (error) {
            toast.error(error.response.data?.msg);
        }
        refetch();
    }

    function fetchVendorUsers() {}

    return (
        <>
            <div className="flex flex-col h-screen">
                <div className="flex items-center justify-between px-4 py-2 bg-gray-800">
                    <h1 className="text-lg font-semibold text-white">
                        Pending Vendor
                    </h1>
                    <button
                        className="px-3 py-1 text-sm font-medium text-white bg-blue-600 rounded hover:bg-blue-500"
                        onClick={fetchVendorUsers}
                        disabled={loading}
                    >
                        {loading ? 'Loading...' : 'Refresh'}
                    </button>
                </div>
                <div className="flex-grow px-4 py-6 overflow-auto">
                    <table className="w-full border-collapse">
                        <thead>
                            <tr>
                                <th className="p-3 font-medium text-left text-gray-800 border border-gray-300">
                                    User
                                </th>
                                <th className="p-3 font-medium text-left text-gray-800 border border-gray-300">
                                    Email
                                </th>
                                <th className="p-3 font-medium text-left text-gray-800 border border-gray-300">
                                    Phone
                                </th>
                                <th className="p-3 font-medium text-left text-gray-800 border border-gray-300">
                                    Action
                                </th>
                            </tr>
                        </thead>
                        <tbody>
                            {vendorUsers?.map((user) => (
                                <tr
                                    key={user._id}
                                    className="border-t border-gray-300"
                                >
                                    <td className="p-3 text-sm font-medium text-gray-800 border border-gray-300">
                                        <img
                                            src={user.user.profile}
                                            alt={user.user.name}
                                            className="w-8 h-8 rounded-full inline-block mr-5"
                                        />
                                        {user.user?.username}
                                    </td>
                                    <td className="p-3 text-sm font-medium text-gray-800 border border-gray-300">
                                        {user.user.email}
                                    </td>
                                    <td className="p-3 text-sm font-medium text-gray-800 border border-gray-300">
                                        {user.user.phone}
                                    </td>
                                    <td className="p-3 text-sm font-medium text-gray-800 border border-gray-300">
                                        <div className="flex items-center">
                                            <button
                                                className="px-2 py-1 text-sm font-medium text-white bg-green-600 rounded hover:bg-green-500 mr-2"
                                                onClick={() =>
                                                    handleApprove(
                                                        true,
                                                        user._id,
                                                    )
                                                }
                                            >
                                                Approve
                                            </button>
                                            <button
                                                className="px-2 py-1 text-sm font-medium text-white bg-red-600 rounded hover:bg-red-500"
                                                onClick={() =>
                                                    handleApprove(
                                                        false,
                                                        user.user._id,
                                                    )
                                                }
                                            >
                                                Reject
                                            </button>
                                        </div>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                    {vendorUsers?.length === 0 && (
                        <p className="mt-4 text-sm font-medium text-gray-700">
                            No vendor users found.
                        </p>
                    )}
                </div>
            </div>
        </>
    );
}

export default VendorApproval;
