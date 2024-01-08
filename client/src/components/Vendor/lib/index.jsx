import {
	HiOutlineViewGrid,
	HiOutlineCube,
	HiOutlineShoppingCart,
	HiOutlineUsers,
	HiOutlineDocumentText,
	HiOutlineAnnotation,
	HiOutlineQuestionMarkCircle,
	HiOutlineCog
} from 'react-icons/hi'

export const DASHBOARD_SIDEBAR_LINKS = [
	{
		key: 'dashboard',
		label: 'Dashboard',
		path: '/vendor',
		icon: <HiOutlineViewGrid />
	},

	{
		key: 'addservice',
		label: 'Add Service',
		path: '/vendor/addservice',
		icon: <HiOutlineUsers />
	},
	{
		key: 'totalorders',
		label: 'Total Orders',
		path: '/vendor/total-orders',
		icon: <HiOutlineShoppingCart />
	},
	{
		key: 'chat',
		label: 'Messages',
		path: '/vendor/chat',
		icon: <HiOutlineUsers />
	},


]

