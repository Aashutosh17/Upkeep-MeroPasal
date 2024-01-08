import React, { useState } from 'react';
// import { ChatIcon } from '@heroicons/react/solid';
import { HiOutlineLogout } from 'react-icons/hi'

const Chat = () => {
    const [isOpen, setIsOpen] = useState(false);
    const [messages, setMessages] = useState([
        { text: "Hi, how can I assist you?", sender: "vendor" },
        { text: "I'm looking for a product, can you help?", sender: "customer" },
    ]);
    const [inputText, setInputText] = useState("");

    const toggleChat = () => setIsOpen(!isOpen);

    const handleInputChange = (event) => {
        setInputText(event.target.value);
    };

    const handleInputKeyPress = (event) => {
        if (event.key === 'Enter' && inputText.trim() !== '') {
            setMessages([
                ...messages,
                { text: inputText, sender: "customer" },
            ]);
            setInputText("");
        }
    };

    return (
        <div className="fixed bottom-0 right-0 p-4">
            <button
                className="flex items-center justify-center p-2 rounded-full bg-blue-500 text-white hover:bg-blue-600 focus:outline-none"
                onClick={toggleChat}
            >
                <HiOutlineLogout lassName="h-6 w-6" />
                {/* <ChatIcon className="h-6 w-6" /> */}
            </button>
            {isOpen && (
                <div className="fixed bottom-16 right-4 w-80 max-h-96 rounded-lg border border-gray-300 bg-white shadow-md overflow-y-scroll">
                    <div className="bg-blue-500 text-white p-2 rounded-t-lg">
                        <h3 className="font-semibold">Customer Service</h3>
                    </div>
                    <div className="p-2">
                        {messages.map((message, index) => (
                            <div key={index} className={`mb-2 ${message.sender === "vendor" ? "text-right" : ""}`}>
                                <div
                                    className={`py-2 px-3 rounded-lg ${message.sender === "vendor" ? "bg-blue-100 text-blue-900" : "bg-gray-100 text-gray-900"}`}
                                >
                                    {message.text}
                                </div>
                            </div>
                        ))}
                    </div>
                    <div className="flex items-center bg-gray-100 p-2 rounded-b-lg">
                        <input
                            type="text"
                            className="flex-grow px-4 py-2 rounded-lg mr-2 border border-gray-300 focus:outline-none focus:border-blue-500"
                            placeholder="Type a message..."
                            value={inputText}
                            onChange={handleInputChange}
                            onKeyPress={handleInputKeyPress}
                        />
                        <button
                            className="p-2 rounded-full bg-blue-500 text-white hover:bg-blue-600 focus:outline-none"
                            onClick={handleInputKeyPress}
                        >
                            Send
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Chat;
