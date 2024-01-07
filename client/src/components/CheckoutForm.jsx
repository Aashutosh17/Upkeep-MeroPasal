import Navbar from './Navbar.jsx';
import Footer from './Footer';
import { useQuery } from '@tanstack/react-query';
import { API } from '../store.js';
import { useSelector } from 'react-redux';
import axios from 'axios';
import { useForm } from 'react-hook-form';
import { useParams } from 'react-router-dom';
import { toast } from 'react-toastify';

const CheckoutForm = () => {
    const { userToken } = useSelector((state) => state.auth);
    const { id } = useParams();

    const { register, handleSubmit, reset } = useForm();

    const { data, isLoading, error } = useQuery(['profile'], () =>
        axios.get(`${API}/auth/user`, {
            headers: { Authorization: `Bearer ${userToken}` },
        }),
    );
    const { data: service } = useQuery(['service'], () =>
        axios.get(`${API}/service/single?id=${id}`, {
            headers: { Authorization: `Bearer ${userToken}` },
        }),
    );

    const submit = async (data) => {
        try {
            console.log({ ...data, serviceId: id });
            const res = await axios.post(
                `${API}/order`,
                { ...data, serviceId: id, userId: service.data.user._id },
                { headers: { Authorization: `Bearer ${userToken}` } },
            );
            console.log(res);
            if (res.status == 200) {
                reset();
                toast.success('Ordered Service!');
            }
        } catch (error) {
            console.log(error);
            toast.error(error.response.data);
        }
    };

    return (
        <>
            <Navbar />
            <div className="isolate bg-white text-black  px-6 sm:py-10 lg:px-8">
                <div className="mx-auto max-w-2xl text-center">
                    {/* <p className="mt-2 text-lg leading-8 text-black">
                        Checkout
                    </p> */}
                </div>
                <form
                    onSubmit={handleSubmit(submit)}
                    className="mx-auto mt-16 max-w-xl sm:mt-20"
                >
                    <div className="sm:col-span-2">
                        <div>
                            <label
                                htmlFor="first-name"
                                className="block text-sm font-semibold leading-6 text-gray-900"
                            >
                                Customer name
                            </label>
                            <div className="mt-2.5">
                                <input
                                    type="text"
                                    name="first-name"
                                    id="first-name"
                                    required
                                    placeholder="Enter First Name"
                                    autoComplete="given-name"
                                    className="block w-full rounded-md border-0 py-2 px-3.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300  sm:text-sm sm:leading-6"
                                    defaultValue={data?.data?.name}
                                    {...register('name')}
                                />
                            </div>
                        </div>

                        <div className="sm:col-span-2">
                            <label
                                htmlFor="topic"
                                className="block text-sm font-semibold leading-6 text-gray-900"
                            >
                                Address
                            </label>
                            <div className="mt-2.5">
                                <input
                                    type="address"
                                    required
                                    name="address"
                                    id="address"
                                    defaultValue={data?.data?.address}
                                    {...register('address')}
                                    placeholder="Enter Address"
                                    className="block w-full rounded-md border-0 py-2 px-3.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 sm:text-sm sm:leading-6"
                                />
                            </div>
                        </div>
                        <div className="sm:col-span-2">
                            <label
                                htmlFor="topic"
                                className="block text-sm font-semibold leading-6 text-gray-900"
                            >
                                Phone Number
                            </label>
                            <div className="mt-2.5">
                                <input
                                    type="phonenumber"
                                    name="phonenumber"
                                    required
                                    id="phonenumber"
                                    defaultValue={data?.data?.phone}
                                    {...register('phone')}
                                    placeholder="Enter Phone Number"
                                    className="block w-full rounded-md border-0 py-2 px-3.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 sm:text-sm sm:leading-6"
                                />
                            </div>
                        </div>
                        <div className="sm:col-span-2">
                            <label
                                htmlFor="topic"
                                className="block text-sm font-semibold leading-6 text-gray-900"
                            >
                                Time
                            </label>
                            <div className="mt-2.5">
                                <input
                                    type="deliverytime"
                                    name="deliverytime"
                                    required
                                    id="deliverytime"
                                    {...register('time')}
                                    placeholder="Enter delivery time"
                                    className="block w-full rounded-md border-0 py-2 px-3.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 sm:text-sm sm:leading-6"
                                />
                            </div>
                        </div>
                    </div>
                    <div className="sm:col-span-2 mt-2">
                        <label
                            htmlFor="topic"
                            className="block text-sm font-semibold leading-6 text-gray-900"
                        >
                            Payment Method
                        </label>
                        <div className="mt-2.5">
                            <select
                                name="paymentmethod"
                                required
                                id="paymentmethod"
                                className="block w-full rounded-md border-0 py-2 px-3.5 text-gray-900 shadow-sm ring-1   ring-gray-300 sm:text-sm sm:leading-6"
                            >
                                <option value="">Select Payment Method</option>
                                <option value="cashondelivery">
                                    Cash on Delivery
                                </option>
                            </select>
                        </div>
                    </div>

                    <div className="mt-10">
                        <button
                            type="submit"
                            className="block w-full rounded-md bg-green-600 px-3.5 py-2.5 text-center text-sm font-semibold text-white shadow-sm hover:bg-red-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-green-600"
                        >
                            Confirm Order
                        </button>
                    </div>
                </form>
            </div>
            <Footer />
        </>
    );
};
export default CheckoutForm;
