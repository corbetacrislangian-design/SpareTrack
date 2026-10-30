const express = require('express');
const router = express.Router();
const apiController = require('../controllers/apiController');
const { authorizeRoles } = require('../middleware/rbac');

// Public Authentication Endpoints
router.post('/auth/login', apiController.login);
router.post('/auth/signup', apiController.signup);
router.post('/auth/logout', apiController.logout);

// Protected Dashboard & Reports Data (Requires Cryptographic Session Token)
router.get('/dashboard', authorizeRoles('ADMIN', 'LOGISTICS_STAFF', 'MAINTENANCE_TECH'), apiController.getDashboardData);

// Tier 1: ADMIN (System Administrator + Manager Functions)
router.post('/users', authorizeRoles('ADMIN'), apiController.createUserByAdmin);
router.patch('/users/:user_id', authorizeRoles('ADMIN'), apiController.updateUserAccess);
router.post('/parts', authorizeRoles('ADMIN'), apiController.createSparePart);
router.put('/parts/:part_id', authorizeRoles('ADMIN'), apiController.updateSparePart);
router.delete('/parts/:part_id', authorizeRoles('ADMIN'), apiController.deleteSparePart);
router.patch('/requests/status', authorizeRoles('ADMIN'), apiController.updateRequestStatus);
router.post('/warehouses', authorizeRoles('ADMIN'), apiController.createWarehouse);
router.post('/machines', authorizeRoles('ADMIN'), apiController.createMachine);
router.patch('/machines/:machine_id/status', authorizeRoles('ADMIN', 'MAINTENANCE_TECH'), apiController.updateMachineStatus);

// Tier 2: LOGISTICS_STAFF (Warehouse Staff + Procurement Officer Functions)
router.post('/inventory/bin', authorizeRoles('LOGISTICS_STAFF', 'ADMIN'), apiController.upsertWarehouseBinStock);
router.post('/inventory/transfer', authorizeRoles('LOGISTICS_STAFF', 'ADMIN'), apiController.transferWarehouseStock);
router.post('/requests/release', authorizeRoles('LOGISTICS_STAFF', 'ADMIN'), apiController.releaseApprovedStock);
router.post('/requests/return', authorizeRoles('LOGISTICS_STAFF', 'MAINTENANCE_TECH', 'ADMIN'), apiController.returnUnusedParts);
router.post('/suppliers', authorizeRoles('LOGISTICS_STAFF', 'ADMIN'), apiController.createSupplier);
router.post('/purchase-orders', authorizeRoles('LOGISTICS_STAFF', 'ADMIN'), apiController.createPurchaseOrder);
router.patch('/purchase-orders/receive', authorizeRoles('LOGISTICS_STAFF', 'ADMIN'), apiController.receivePurchaseOrder);

// Tier 3: MAINTENANCE_TECH (Maintenance Staff Functions)
router.post('/requests', authorizeRoles('MAINTENANCE_TECH', 'ADMIN'), apiController.createMaintenanceRequest);

module.exports = router;