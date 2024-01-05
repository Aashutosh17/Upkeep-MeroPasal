import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';
import { API } from '../../../store';

export const authApi = createApi({
    reducerPath: 'authApi',
    baseQuery: fetchBaseQuery({
        baseUrl: `${API}`,
        // baseUrl: 'http://127.0.0.1:5000/',
        prepareHeaders: (headers, { getState }) => {
            const token = getState().auth.userToken;

            if (token) {
                headers.set('authorization', `Bearer ${token}`);
                return headers;
            }
        },
    }),
    endpoints: (build) => ({
        getDetails: build.query({
            query: () => ({
                url: 'auth/user',
                method: 'GET',
            }),
        }),
    }),
});

// export react hook
export const { useGetDetailsQuery } = authApi;
