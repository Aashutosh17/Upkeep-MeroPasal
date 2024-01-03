import { Router } from 'express';
import {
    approveOrRejectVendors,
    createCategory,
    deleteCategory,
    deleteService,
    getCategories,
    getPendingVendors,
    getServices,
} from '../controllers/admin.controller.js';
import { verifyAdmin, useLogin } from '../middlewares/auth.js';

const adminRouter = Router();

adminRouter.post('/category', useLogin, verifyAdmin, createCategory);

adminRouter.get('/category', getCategories);
adminRouter.delete('/category', deleteCategory);

adminRouter.get('/pending_vendors', getPendingVendors);
adminRouter.patch('/vendor', useLogin, verifyAdmin, approveOrRejectVendors);
adminRouter.get('/service', useLogin, verifyAdmin, getServices);
adminRouter.delete('/service', useLogin, verifyAdmin, deleteService);

export default adminRouter;
