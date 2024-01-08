import { useState, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';
import { useSelector } from 'react-redux';
import { API } from '../../../store';
import { useForm } from 'react-hook-form';
import Spinner from '../../Spinner';
import { AiOutlineDelete } from 'react-icons/ai';
import { toast } from 'react-toastify';

const CreateCategory = ({ onSubmit }) => {
    const { userToken } = useSelector((state) => state.auth);
    const { register, handleSubmit, reset } = useForm();
    const [msg, setMsg] = useState('');
    const queryClient = useQueryClient();

    // useEffect(() => {
    //     async function getCat() {
    //         const data = await axios.get(`${API}/admin/category`, {
    //             headers: { Authorization: `Bearer ${userToken}` },
    //         });
    //         console.log(data);
    //     }
    //     getCat();
    // }, []);

    const { data, isLoading, error, refetch } = useQuery(['category'], () =>
        axios.get(`${API}/admin/category`),
    );

    const submitForm = (data) => {
        console.log(data);
        async function createCategory() {
            const res = await axios.post(
                `${API}/admin/category`,
                { name: data.category },
                {
                    headers: { Authorization: `Bearer ${userToken}` },
                },
            );
            // console.log(res);
            queryClient.invalidateQueries('category');
        }
        createCategory();
        reset();
    };
    const deleteCategory = async (id) => {
        const data = await axios.delete(
            `${API}/admin/category?id=${id}`,
            {},
            {
                headers: { Authorization: `Bearer ${userToken}` },
            },
        );
        toast.success(data.data);
        queryClient.invalidateQueries('category');
    };

    return (
        <>
            <form
                onSubmit={handleSubmit(submitForm)}
                className="w-full max-w-sm  ml-10   mt-12"
            >
                <div className="mb-4">
                    {msg}
                    <label
                        htmlFor="category-name"
                        className="block text-gray-700 font-bold mb-2 text-1xl"
                    >
                        Category Name
                    </label>
                    <input
                        type="text"
                        id="category-name"
                        {...register('category')}
                        className="appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
                        required
                    />
                </div>

                <div className="flex items-center justify-start">
                    <button
                        type="submit"
                        className="bg-green-500 hover:bg-green-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
                    >
                        Create
                    </button>
                </div>
            </form>
            <div className="w-48 ml-10 ">
                {isLoading ? (
                    <Spinner />
                ) : (
                    data?.data?.map((item) => (
                        <div
                            className="bg-black text-white rounded my-5 py-2 px-5 flex align-middle justify-between"
                            key={item._id}
                        >
                            {item.name}
                            <button
                                onClick={(e) => deleteCategory(item._id)}
                                className="text-red-500 hover:text-red-600"
                            >
                                <AiOutlineDelete size={18} />
                            </button>
                        </div>
                    ))
                )}
            </div>
        </>
    );
};

export default CreateCategory;
