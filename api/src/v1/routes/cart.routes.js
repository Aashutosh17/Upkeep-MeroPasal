import { Router } from 'express';
import {
    addCartItems,
    getCart,
    toggleCartChecked,
} from '../controllers/cart.controller.js';
import { useLogin } from '../middlewares/auth.js';

const cartRouter = Router();

cartRouter.post('/add/:id', useLogin, addCartItems);
cartRouter.get('/toggle', useLogin, toggleCartChecked);
cartRouter.get('/', useLogin, getCart);

export default cartRouter;
