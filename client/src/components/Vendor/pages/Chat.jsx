import React from 'react';

const Chat = () => {
    return (
        <div className="w-full max-w-screen-xl mx-auto bg-white rounded-lg shadow-lg overflow-hidden">
            {/* Chatbox header */}
            {/* <div className="px-6 py-4 bg-gray-200">
                <h2 className="text-lg font-bold text-gray-800">Chat with Support</h2>
                <p className="text-sm font-medium text-gray-500">Welcome! How may we assist you?</p>
            </div> */}

            {/* Chatbox messages */}
            <div className="px-6 py-4">
                {/* Sample message */}
                <div className="flex items-end mb-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gray-400"></div>
                    <div className="ml-3 bg-gray-100 py-2 px-3 rounded-lg">
                        <p className="text-sm text-gray-600">Hi there, how can I help you today?</p>
                    </div>
                </div>

                {/* Sample message */}
                <div className="flex items-end justify-end mb-4">
                    <div className="mr-3 bg-blue-600 py-2 px-3 rounded-lg">
                        <p className="text-sm text-white">Sure, what's your order number?</p>
                    </div>
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gray-400"></div>
                </div>

                {/* Sample message */}
                <div className="flex items-end mb-4">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-gray-400"></div>
                    <div className="ml-3 bg-gray-100 py-2 px-3 rounded-lg">
                        <p className="text-sm text-gray-600">Thank you, your order number is XYZ123.</p>
                    </div>
                </div>
            </div>

            {/* Chatbox input */}
            <div className="px-6 py-4 bg-gray-200">
                <form>
                    <div className="flex items-center">
                        <input
                            type="text"
                            className="bg-white border border-gray-400  py-2 px-4 flex-1 mr-3 text-sm focus:outline-none focus:shadow-outline-blue"
                            placeholder="Type your message..."
                        />
                        <button
                            type="submit"
                            className="bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:shadow-outline-blue"
                        >
                            Send
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
};

export default Chat;
