import { FaStar } from 'react-icons/fa';

const Rating = ({ value, readOnly }) => {
    const stars = [];

    for (let i = 1; i <= 5; i++) {
        stars.push(
            <FaStar
                key={i}
                className={`text-2xl ${
                    i <= value ? 'text-yellow-400' : 'text-gray-300'
                } ${readOnly ? 'pointer-events-none' : ''}`}
            />,
        );
    }

    return (
        <div className="flex items-center">
            {stars}
            <span className="ml-2">{value}</span>
        </div>
    );
};

export default Rating;
