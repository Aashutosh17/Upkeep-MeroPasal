import { Router } from 'express';
import {
    changeStatus,
    getOrders,
    orderService,
} from '../controllers/order.controller.js';
import { useLogin } from '../middlewares/auth.js';
import { getCart, toggleCartChecked } from '../controllers/cart.controller.js';

const orderRouter = Router();

orderRouter.post('/', useLogin, orderService);
orderRouter.get('/', useLogin, getOrders);
orderRouter.patch('/', useLogin, changeStatus);
orderRouter.post('/toggle', useLogin, toggleCartChecked);

export default orderRouter;
