import React, { useState } from 'react';
import axios from 'axios';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { API } from '../../../store';
import { useSelector } from 'react-redux';
import { toast } from 'react-toastify';

function Service() {
    const { userToken } = useSelector((state) => state.auth);
    const queryClient = useQueryClient();
    const [loading, setLoading] = useState(false);

    const { data, isLoading, refetch } = useQuery(['getservices'], async () => {
        const response = await axios.get(`${API}/admin/service`, {
            headers: { Authorization: `Bearer ${userToken}` },
        });
        return response.data;
    });

    async function deleteService(id) {
        const data = await axios.delete(`${API}/admin/service?id=${id}`, {
            headers: { Authorization: `Bearer ${userToken}` },
        });

        if (data.status === 200) {
            toast.success('Service deleted');
            queryClient.invalidateQueries('getservices');
        }
    }

    // const { data: info, isLoading } = useQuery(['delete-service'], )

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

    return (
        <>
            <div className="flex flex-col h-screen">
                <div className="flex items-center justify-between px-4 py-2 bg-gray-800">
                    <h1 className="text-lg font-semibold text-white">
                        Services
                    </h1>
                    <button
                        className="px-3 py-1 text-sm font-medium text-white bg-blue-600 rounded hover:bg-blue-500"
                        disabled={loading}
                    >
                        {loading ? 'Loading...' : 'Refresh'}
                    </button>
                </div>
                <div className="flex-grow gap-11  px-4 py-6 overflow-auto">
                    {data?.map((service, index) => (
                        <div
                            key={index}
                            className="p-4 mb-10 bg-white rounded-lg shadow-md"
                        >
                            <h3 className="text-lg font-medium mb-2">
                                {service.title}
                            </h3>
                            {/* <img src={service?.image} alt="" /> */}
                            <p className="text-gray-500 mb-4">{service.desc}</p>
                            <p className="text-gray-600 font-medium mb-2">
                                ${service.price}
                            </p>
                            <button
                                onClick={(e) => deleteService(service._id)}
                                className="bg-blue-500 hover:bg-blue-900 text-white p-2 rounded"
                            >
                                Delete Service
                            </button>
                        </div>
                    ))}
                </div>
            </div>
        </>
    );
}

export default Service;
