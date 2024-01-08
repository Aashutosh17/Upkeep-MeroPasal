import {
	HiOutlineViewGrid,
	HiOutlineCube,
	HiOutlineAnnotation,
} from 'react-icons/hi'

export const DASHBOARD_SIDEBAR_LINKS_VENDORS = [
	{
		key: 'dashboard',
		label: 'Dashboard',
		path: '/',
		icon: <HiOutlineViewGrid />
	},
	{
		key: 'totalcustomer',
		label: 'Total Customers',
		path: '/totalcustomer',
		icon: <HiOutlineCube />
	},
	{
		key: 'chat',
		label: 'Chatbox',
		path: '/chat',
		icon: <HiOutlineAnnotation />
	}
]

