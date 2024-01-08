import {
    HiOutlineViewGrid,
    HiOutlineCube,
    HiOutlineShoppingCart,
    HiOutlineUsers,
    HiOutlineDocumentText,
    HiOutlineAnnotation,
    HiOutlineQuestionMarkCircle,
    HiOutlineCog,
} from 'react-icons/hi';

export const DASHBOARD_SIDEBAR_LINKS = [
    {
        key: 'dashboard',
        label: 'Dashboard',
        path: '/admin',
        icon: <HiOutlineViewGrid />,
    },
    {
        key: 'totalcustomer',
        label: 'Total Customer',
        path: '/admin/totalcustomer',
        icon: <HiOutlineCube />,
    },
    {
        key: 'totalvendor',
        label: 'Total Vendor',
        path: '/admin/totalvendor',
        icon: <HiOutlineShoppingCart />,
    },
    {
        key: 'approvals',
        label: 'Approvals',
        path: '/admin/vendor-approval',
        icon: <HiOutlineUsers />,
    },
    {
        key: 'createcategory',
        label: 'Create Category',
        path: '/admin/create-category',
        icon: <HiOutlineUsers />,
    },
    {
        key: 'services',
        label: 'Services',
        path: '/admin/services',
        icon: <HiOutlineUsers />,
    },
];
