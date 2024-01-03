import { Router } from 'express';
import {
    getAllUsers,
    getAllVendors,
    requestVendor,
    updateProfile,
    updateUser,
} from '../controllers/user.controller.js';
import { verifyAdmin, useLogin } from '../middlewares/auth.js';
import { upload } from '../middlewares/uploadImage.js';

const usersRouter = Router();
/* GET users listing. */
usersRouter.get('/', useLogin, verifyAdmin, getAllUsers);
usersRouter.get('/vendor', useLogin, verifyAdmin, getAllVendors);
usersRouter.post('/vendor', useLogin, requestVendor);
usersRouter.patch('/update', useLogin, updateUser);
usersRouter.post('/profile', useLogin, upload.single('images'), updateProfile);

export default usersRouter;
