import {
	HiOutlineViewGrid,
	HiOutlineCube,
	HiOutlineShoppingCart,
	HiOutlineUsers,
	HiOutlineAnnotation,
} from 'react-icons/hi'

export const DASHBOARD_SIDEBAR_LINKS = [
	{
		key: 'dashboard',
		label: 'Dashboard',
		path: '/vendor-dashboard',
		icon: <HiOutlineViewGrid />
	},
	{
		key: 'totalcustomer',
		label: 'Total Customers',
		path: '/totalcustomer',
		icon: <HiOutlineCube />
	},
	{
		key: 'totalvendor',
		label: 'Total Vendors',
		path: '/totalvendor',
		icon: <HiOutlineShoppingCart />
	},
	{
		key: 'approval',
		label: 'Approvals	',
		path: '/approval',
		icon: <HiOutlineUsers />
	},

	{
		key: 'chat',
		label: 'Chatbox',
		path: '/chat',
		icon: <HiOutlineAnnotation />
	}
]

