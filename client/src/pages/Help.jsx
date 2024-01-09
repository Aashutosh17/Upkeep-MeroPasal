import { useState } from 'react';
import { useForm } from 'react-hook-form';

const Help = () => {
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [formSubmitted, setFormSubmitted] = useState(false);
    const {
        register,
        handleSubmit,
        formState: { errors },
    } = useForm();

    const onSubmit = async (data) => {
        setIsSubmitting(true);

        // Here you can implement your logic to send the form data to your backend

        setIsSubmitting(false);
        setFormSubmitted(true);
    };

    return (
        <div className="flex flex-col items-center justify-center h-screen bg-red-400">
            <h1 className="text-3xl font-bold mb-6">Contact Us</h1>
            <form
                onSubmit={handleSubmit(onSubmit)}
                className="w-full md:w-1/2 lg:w-1/3"
            >
                <div className="space-y-4">
                    <div>
                        <label
                            htmlFor="name"
                            className="block font-medium mb-1"
                        >
                            Name
                        </label>
                        <input
                            type="text"
                            id="name"
                            {...register('name', { required: true })}
                            className={`w-full p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                                errors.name ? 'border-red-500' : ''
                            }`}
                        />
                        {errors.name && (
                            <p className="text-red-500 text-sm">
                                Name is required
                            </p>
                        )}
                    </div>
                    <div>
                        <label
                            htmlFor="email"
                            className="block font-medium mb-1"
                        >
                            Email
                        </label>
                        <input
                            type="email"
                            id="email"
                            {...register('email', { required: true })}
                            className={`w-full p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                                errors.email ? 'border-red-500' : ''
                            }`}
                        />
                        {errors.email && (
                            <p className="text-red-500 text-sm">
                                Email is required
                            </p>
                        )}
                    </div>
                    <div>
                        <label
                            htmlFor="message"
                            className="block font-medium mb-1"
                        >
                            Message
                        </label>
                        <textarea
                            id="message"
                            {...register('message', { required: true })}
                            className={`w-full p-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 ${
                                errors.message ? 'border-red-500' : ''
                            }`}
                        ></textarea>
                        {errors.message && (
                            <p className="text-red-500 text-sm">
                                Message is required
                            </p>
                        )}
                    </div>
                    <button
                        type="submit"
                        className={`w-full py-2 px-4 font-semibold rounded-md ${
                            isSubmitting
                                ? 'bg-gray-300 cursor-not-allowed'
                                : 'bg-blue-500 hover:bg-blue-600 text-white'
                        }`}
                        disabled={isSubmitting}
                    >
                        {isSubmitting ? 'Submitting...' : 'Submit'}
                    </button>
                    {formSubmitted && (
                        <p className="text-green-500">
                            Form submitted successfully
                        </p>
                    )}
                </div>
            </form>
        </div>
    );
};

export default Help;
