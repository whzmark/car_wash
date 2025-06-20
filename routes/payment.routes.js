import express from 'express';
import {
  createPayment,
  getAllPayments,
  getDailyReport,
  getInvoice,
  getPaymentById
} from '../controllers/payment.controller.js';
import { requireAuth } from '../middleware/authMiddleware.js';


const router = express.Router();

router.post('/', requireAuth, createPayment);
router.get('/', requireAuth, getAllPayments);
router.get('/:id', requireAuth, getPaymentById);
router.get('/:id/invoice', requireAuth, getInvoice);
router.get('/report/daily', requireAuth, getDailyReport);

export default router;
