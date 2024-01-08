import React from 'react';
import { Outlet } from 'react-router-dom';

export default function Wrapper() {
    return (
        <div className="bg-neutral-100 h-screen w-screen overflow-hidden flex flex-row">
            <div className="flex-1 p-4 min-h-0 overflow-auto">
                <Outlet />
            </div>
        </div>
    );
}
