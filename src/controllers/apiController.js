const crypto = require('crypto');
const sequelize = require('../config/db');
const { QueryTypes } = require('sequelize');
const { createSession, destroySession } = require('../middleware/rbac');

// Brute-force login protection tracker
const loginAttempts = new Map();
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_TIME_MS = 60 * 1000; // 60 seconds lockout

// ============================================================================
// SECURITY, CRYPTOGRAPHY & INPUT VALIDATION HELPERS
// ============================================================================

function sanitizeText(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[<>]/g, '').trim();
}

function validateEmail(email) {
  const clean = String(email || '').trim().toLowerCase();
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  if (!emailRegex.test(clean)) {
    return 'Invalid email format. Email must include "@" and a valid domain (e.g. user@company.com).';
  }
  return null;
}

function validatePassword(password) {
  const pw = String(password || '');
  const missing = [];
  if (pw.length < 8) missing.push('at least 8 characters');
  if (!/[A-Z]/.test(pw)) missing.push('an uppercase letter (A-Z)');
  if (!/[a-z]/.test(pw)) missing.push('a lowercase letter (a-z)');
  if (!/[0-9]/.test(pw)) missing.push('a number (0-9)');
  if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?~`]/.test(pw)) {
    missing.push('a special symbol (e.g. !@#$%^&*)');
  }
  if (missing.length > 0) {
    return `Password must contain ${missing.join(', ')}.`;
  }
  return null;
}

function validateUsername(username) {
  const clean = String(username || '').trim();
  if (!/^[a-zA-Z0-9_]{4,30}$/.test(clean)) {
    return 'Username must be 4–30 characters and contain only letters, numbers, or underscores.';
  }
  return null;
}

function validatePhone(phone) {
  const clean = String(phone || '').trim();
  if (!/^\+?[0-9\-\s()]{7,20}$/.test(clean)) {
    return 'Invalid phone number format (use 7–20 digits, +, -, or spaces).';
  }
  return null;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt$${salt}$${derivedKey}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash) return false;
  if (storedHash.startsWith('scrypt$')) {
    const parts = storedHash.split('$');
    if (parts.length !== 3) return false;
    const salt = parts[1];
    const originalHash = Buffer.from(parts[2], 'hex');
    const candidateHash = crypto.scryptSync(password, salt, 64);
    return crypto.timingSafeEqual(originalHash, candidateHash);
  }
  const expectedSeedHash = 'hashed_pw_' + password;
  return storedHash === password || storedHash === expectedSeedHash;
}

// ============================================================================
// AUTOMATIC AUDIT LOG SCHEMA & TRIGGER INITIALIZATION
// ============================================================================
let auditSystemInitialized = false;

async function ensureAuditSystem() {
  if (auditSystemInitialized) return;
  try {
    await sequelize.query(`
      ALTER TABLE inventory_audit_logs
      MODIFY COLUMN warehouse_id INT NULL,
      MODIFY COLUMN part_id INT NULL,
      MODIFY COLUMN old_qty INT NOT NULL DEFAULT 0,
      MODIFY COLUMN new_qty INT NOT NULL DEFAULT 0,
      MODIFY COLUMN qty_delta INT NOT NULL DEFAULT 0,
      MODIFY COLUMN storage_bin_snapshot VARCHAR(40) NOT NULL DEFAULT '-'
    `);

    const alterColumns = [
      `ALTER TABLE inventory_audit_logs ADD COLUMN actor_user_id INT NULL AFTER log_id`,
      `ALTER TABLE inventory_audit_logs ADD COLUMN module_name VARCHAR(50) NOT NULL DEFAULT 'Inventory' AFTER actor_user_id`,
      `ALTER TABLE inventory_audit_logs ADD COLUMN activity_details VARCHAR(255) NULL AFTER action_type`
    ];

    for (const sql of alterColumns) {
      try {
        await sequelize.query(sql);
      } catch (err) {
        // Ignore if column already exists
      }
    }

    await sequelize.query(`DROP PROCEDURE IF EXISTS sp_record_audit_log`);
    await sequelize.query(`
      CREATE PROCEDURE sp_record_audit_log(
        IN p_user_id INT,
        IN p_module VARCHAR(50),
        IN p_action VARCHAR(50),
        IN p_details VARCHAR(255),
        IN p_warehouse_id INT,
        IN p_part_id INT
      )
      BEGIN
        INSERT INTO inventory_audit_logs (
          actor_user_id, module_name, warehouse_id, part_id, action_type,
          activity_details, old_qty, new_qty, qty_delta, storage_bin_snapshot
        ) VALUES (
          p_user_id, p_module, p_warehouse_id, p_part_id, p_action,
          p_details, 0, 0, 0, '-'
        );
      END
    `);

    await sequelize.query(`DROP TRIGGER IF EXISTS trg_audit_inventory_update`);
    await sequelize.query(`
      CREATE TRIGGER trg_audit_inventory_update
      AFTER UPDATE ON warehouse_inventory
      FOR EACH ROW
      BEGIN
        IF OLD.current_qty <> NEW.current_qty THEN
          INSERT INTO inventory_audit_logs (
            actor_user_id, module_name, warehouse_id, part_id, action_type,
            activity_details, old_qty, new_qty, qty_delta, storage_bin_snapshot
          ) VALUES (
            @current_actor_id,
            'Inventory',
            NEW.warehouse_id,
            NEW.part_id,
            IF(NEW.current_qty > OLD.current_qty, 'Stock In', 'Stock Out'),
            CONCAT('Bin ', NEW.storage_bin_location, ' adjusted from ', OLD.current_qty, ' to ', NEW.current_qty),
            OLD.current_qty,
            NEW.current_qty,
            (NEW.current_qty - OLD.current_qty),
            NEW.storage_bin_location
          );
        END IF;
      END
    `);

    await sequelize.query(`DROP TRIGGER IF EXISTS trg_audit_request_insert`);
    await sequelize.query(`
      CREATE TRIGGER trg_audit_request_insert
      AFTER INSERT ON maintenance_requests
      FOR EACH ROW
      BEGIN
        INSERT INTO inventory_audit_logs (
          actor_user_id, module_name, warehouse_id, part_id, action_type,
          activity_details, old_qty, new_qty, qty_delta, storage_bin_snapshot
        ) VALUES (
          NEW.requested_by,
          'Part Requests',
          NEW.warehouse_id,
          NULL,
          'Submitted Request',
          CONCAT('Submitted request ', NEW.request_number, ' (', NEW.priority, ') - ', NEW.maintenance_task_desc),
          0, 0, 0, '-'
        );
      END
    `);

    await sequelize.query(`DROP TRIGGER IF EXISTS trg_audit_request_status`);
    await sequelize.query(`
      CREATE TRIGGER trg_audit_request_status
      AFTER UPDATE ON maintenance_requests
      FOR EACH ROW
      BEGIN
        IF OLD.status <> NEW.status THEN
          INSERT INTO inventory_audit_logs (
            actor_user_id, module_name, warehouse_id, part_id, action_type,
            activity_details, old_qty, new_qty, qty_delta, storage_bin_snapshot
          ) VALUES (
            COALESCE(@current_actor_id, NEW.approved_by, NEW.requested_by),
            'Part Requests',
            NEW.warehouse_id,
            NULL,
            CASE NEW.status
              WHEN 'APPROVED' THEN 'Approved Request'
              WHEN 'REJECTED' THEN 'Rejected Request'
              WHEN 'RELEASED' THEN 'Released Request Stock'
              ELSE NEW.status
            END,
            CONCAT('Request ', NEW.request_number, ' marked as ', NEW.status),
            0, 0, 0, '-'
          );
        END IF;
      END
    `);

    await sequelize.query(`DROP TRIGGER IF EXISTS trg_audit_po_insert`);
    await sequelize.query(`
      CREATE TRIGGER trg_audit_po_insert
      AFTER INSERT ON purchase_orders
      FOR EACH ROW
      BEGIN
        INSERT INTO inventory_audit_logs (
          actor_user_id, module_name, warehouse_id, part_id, action_type,
          activity_details, old_qty, new_qty, qty_delta, storage_bin_snapshot
        ) VALUES (
          NEW.created_by,
          'Purchase Orders',
          NEW.warehouse_id,
          NEW.part_id,
          'Created Order',
          CONCAT('Issued ', NEW.po_number, ' for ', NEW.ordered_qty, ' units at PHP ', NEW.unit_price),
          0, 0, 0, '-'
        );
      END
    `);

    await sequelize.query(`DROP TRIGGER IF EXISTS trg_audit_po_status`);
    await sequelize.query(`
      CREATE TRIGGER trg_audit_po_status
      AFTER UPDATE ON purchase_orders
      FOR EACH ROW
      BEGIN
        IF OLD.po_status <> NEW.po_status THEN
          INSERT INTO inventory_audit_logs (
            actor_user_id, module_name, warehouse_id, part_id, action_type,
            activity_details, old_qty, new_qty, qty_delta, storage_bin_snapshot
          ) VALUES (
            COALESCE(@current_actor_id, NEW.created_by),
            'Purchase Orders',
            NEW.warehouse_id,
            NEW.part_id,
            'Received Delivery',
            CONCAT('Order ', NEW.po_number, ' marked as ', NEW.po_status, ' (+', NEW.ordered_qty, ' units restocked)'),
            0, 0, 0, '-'
          );
        END IF;
      END
    `);

    await sequelize.query(`
      UPDATE inventory_audit_logs
      SET activity_details = CONCAT('Bin ', storage_bin_snapshot, ' adjusted from ', old_qty, ' to ', new_qty),
          actor_user_id = COALESCE(actor_user_id, 2)
      WHERE activity_details IS NULL
    `);

    auditSystemInitialized = true;
  } catch (err) {
    console.error('Audit system init warning:', err.message);
  }
}

async function logActivity(userId, moduleName, actionType, details, warehouseId = null, partId = null) {
  try {
    await ensureAuditSystem();
    await sequelize.query(
      `CALL sp_record_audit_log(:userId, :moduleName, :actionType, :details, :warehouseId, :partId)`,
      {
        replacements: {
          userId: userId ? Number(userId) : null,
          moduleName,
          actionType,
          details: sanitizeText(details).slice(0, 250),
          warehouseId: warehouseId ? Number(warehouseId) : null,
          partId: partId ? Number(partId) : null
        }
      }
    );
  } catch (err) {
    console.error('Audit log error:', err.message);
  }
}

// ============================================================================
// HARDENED AUTHENTICATION CONTROLLERS (LOGIN, SIGN UP, LOGOUT)
// ============================================================================

exports.login = async (req, res) => {
  try {
    await ensureAuditSystem();
    const identifier = sanitizeText(req.body.username);
    const password = String(req.body.password || '');

    if (!identifier || !password) {
      return res.status(400).json({ error: 'Username/Email and password are required.' });
    }

    const attemptKey = identifier.toLowerCase();
    const record = loginAttempts.get(attemptKey);
    if (record && record.count >= MAX_LOGIN_ATTEMPTS && Date.now() < record.lockUntil) {
      const waitSec = Math.ceil((record.lockUntil - Date.now()) / 1000);
      return res.status(429).json({
        error: `Too many failed login attempts. Account locked for ${waitSec} seconds.`
      });
    }

    const users = await sequelize.query(
      `SELECT u.user_id, u.username, u.password_hash, u.full_name, u.email, u.role,
              u.assigned_warehouse_id, u.is_active, w.warehouse_code, w.warehouse_name
       FROM users u
       LEFT JOIN warehouses w ON u.assigned_warehouse_id = w.warehouse_id
       WHERE LOWER(u.username) = LOWER(:identifier) OR LOWER(u.email) = LOWER(:identifier)
       LIMIT 1`,
      {
        replacements: { identifier },
        type: QueryTypes.SELECT
      }
    );

    if (!users.length || !verifyPassword(password, users[0].password_hash)) {
      const prev = loginAttempts.get(attemptKey) || { count: 0, lockUntil: 0 };
      prev.count += 1;
      if (prev.count >= MAX_LOGIN_ATTEMPTS) {
        prev.lockUntil = Date.now() + LOCKOUT_TIME_MS;
      }
      loginAttempts.set(attemptKey, prev);

      await logActivity(
        users.length ? users[0].user_id : null,
        'Security',
        'Failed Sign In',
        `Failed login attempt for identifier '${identifier}' (Attempt ${prev.count}/${MAX_LOGIN_ATTEMPTS})`,
        null,
        null
      );

      return res.status(401).json({ error: 'Invalid username/email or password.' });
    }

    const user = users[0];
    if (!user.is_active) {
      return res.status(403).json({ error: 'Account is deactivated. Contact the Administrator.' });
    }

    loginAttempts.delete(attemptKey);

    // Issue Cryptographic HMAC-SHA256 Token + HttpOnly Cookie
    const sessionToken = createSession(user, req, res);

    await logActivity(
      user.user_id,
      'Authentication',
      'Signed In',
      `${user.full_name} (${user.role}) signed in with verified session token`,
      user.assigned_warehouse_id,
      null
    );

    res.json({
      message: 'Authentication successful.',
      token: sessionToken,
      user: {
        user_id: user.user_id,
        username: user.username,
        full_name: user.full_name,
        email: user.email,
        role: user.role,
        assigned_warehouse_id: user.assigned_warehouse_id,
        warehouse_code: user.warehouse_code || 'ALL'
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

exports.signup = async (req, res) => {
  try {
    await ensureAuditSystem();
    const username = sanitizeText(req.body.username);
    const full_name = sanitizeText(req.body.full_name);
    const email = sanitizeText(req.body.email).toLowerCase();
    const password = String(req.body.password || '');
    const role = sanitizeText(req.body.role);
    const assigned_warehouse_id = Number(req.body.assigned_warehouse_id || 1);

    if (!username || !password || !full_name || !email || !role) {
      return res.status(400).json({ error: 'All required fields must be filled.' });
    }

    // BLOCK INSPECT ELEMENT PRIVILEGE ESCALATION: Public signup can NEVER self-assign ADMIN
    if (role === 'ADMIN') {
      await logActivity(
        null,
        'Security',
        'Privilege Escalation Blocked',
        `Blocked Inspect Element attempt to self-register ADMIN account (${username} / ${email})`,
        null,
        null
      );
      return res.status(403).json({
        error: 'Security Violation: Administrator accounts cannot be self-registered. Only an existing Administrator can grant ADMIN privileges.'
      });
    }

    const allowedPublicRoles = ['LOGISTICS_STAFF', 'MAINTENANCE_TECH'];
    if (!allowedPublicRoles.includes(role)) {
      return res.status(400).json({ error: 'Invalid role selected.' });
    }

    if (full_name.length < 3 || full_name.length > 100) {
      return res.status(400).json({ error: 'Full name must be between 3 and 100 characters.' });
    }

    const usernameErr = validateUsername(username);
    if (usernameErr) return res.status(400).json({ error: usernameErr });

    const emailErr = validateEmail(email);
    if (emailErr) return res.status(400).json({ error: emailErr });

    const passwordErr = validatePassword(password);
    if (passwordErr) return res.status(400).json({ error: passwordErr });

    const existing = await sequelize.query(
      `SELECT username, email FROM users WHERE LOWER(email) = LOWER(:email) OR LOWER(username) = LOWER(:username) LIMIT 1`,
      {
        replacements: { email, username },
        type: QueryTypes.SELECT
      }
    );

    if (existing.length > 0) {
      if (existing[0].email.toLowerCase() === email) {
        return res.status(409).json({ error: 'This email address is already registered to another account.' });
      }
      return res.status(409).json({ error: 'This username is already taken. Please choose another.' });
    }

    const whCheck = await sequelize.query(
      `SELECT warehouse_id FROM warehouses WHERE warehouse_id = :whId LIMIT 1`,
      { replacements: { whId: assigned_warehouse_id }, type: QueryTypes.SELECT }
    );
    if (!whCheck.length) {
      return res.status(400).json({ error: `Warehouse ID #${assigned_warehouse_id} does not exist.` });
    }

    const password_hash = hashPassword(password);
    const [insertId] = await sequelize.query(
      `INSERT INTO users (username, password_hash, full_name, email, role, assigned_warehouse_id, is_active)
       VALUES (:username, :password_hash, :full_name, :email, :role, :assigned_warehouse_id, TRUE)`,
      {
        replacements: {
          username,
          password_hash,
          full_name,
          email,
          role,
          assigned_warehouse_id
        },
        type: QueryTypes.INSERT
      }
    );

    const newUser = {
      user_id: insertId,
      username,
      full_name,
      email,
      role,
      assigned_warehouse_id
    };

    const sessionToken = createSession(newUser, req, res);

    await logActivity(
      insertId,
      'Users',
      'Account Registered',
      `Registered account '${username}' (${email}) with role ${role}`,
      assigned_warehouse_id,
      null
    );

    res.json({
      message: 'Account created.',
      token: sessionToken,
      user: newUser
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

exports.logout = async (req, res) => {
  destroySession(req, res);
  res.json({ message: 'Signed out.' });
};

// ============================================================================
// CORE DASHBOARD, AUDIT LOGS & ANALYTICAL REPORTS (ROLE-ISOLATED)
// ============================================================================

exports.getDashboardData = async (req, res) => {
  try {
    await ensureAuditSystem();
    const role = req.user.role;
    const isAdmin = role === 'ADMIN';
    const isLogistics = role === 'LOGISTICS_STAFF' || isAdmin;

    const [
      users,
      warehouses,
      suppliers,
      machines,
      parts,
      inventory,
      lowStock,
      requests,
      purchaseOrders,
      auditLogs,
      machineUsageReport,
      supplierSpendReport,
      warehouseValuationReport
    ] = await Promise.all([
      isAdmin
        ? sequelize.query(
            `SELECT u.user_id, u.username, u.full_name, u.email, u.role, u.assigned_warehouse_id, u.is_active, u.created_at, w.warehouse_code
             FROM users u
             LEFT JOIN warehouses w ON u.assigned_warehouse_id = w.warehouse_id
             ORDER BY u.user_id`,
            { type: QueryTypes.SELECT }
          )
        : Promise.resolve([]),
      sequelize.query('SELECT * FROM warehouses ORDER BY warehouse_id', { type: QueryTypes.SELECT }),
      isLogistics
        ? sequelize.query('SELECT * FROM suppliers ORDER BY supplier_id', { type: QueryTypes.SELECT })
        : Promise.resolve([]),
      sequelize.query('SELECT * FROM machines ORDER BY machine_id', { type: QueryTypes.SELECT }),
      sequelize.query('SELECT * FROM spare_parts ORDER BY part_id', { type: QueryTypes.SELECT }),
      sequelize.query(
        `SELECT wi.*, w.warehouse_code, w.warehouse_name, sp.part_number, sp.part_name,
                sp.category, sp.unit_of_measure, sp.unit_cost, sp.reorder_level,
                (wi.current_qty - wi.reserved_qty) AS available_qty
         FROM warehouse_inventory wi
         JOIN warehouses w ON wi.warehouse_id = w.warehouse_id
         JOIN spare_parts sp ON wi.part_id = sp.part_id
         ORDER BY wi.warehouse_id, sp.part_number`,
        { type: QueryTypes.SELECT }
      ),
      isLogistics
        ? sequelize.query('SELECT * FROM v_low_stock_alerts', { type: QueryTypes.SELECT })
        : Promise.resolve([]),
      sequelize.query(
        `SELECT mr.*, m.machine_code, m.machine_name, w.warehouse_code, u.full_name AS requester_name,
                a.full_name AS approver_name, ri.request_item_id, ri.part_id, sp.part_number,
                sp.part_name, ri.requested_qty, ri.issued_qty, ri.returned_qty, ri.usage_notes
         FROM maintenance_requests mr
         JOIN machines m ON mr.machine_id = m.machine_id
         JOIN warehouses w ON mr.warehouse_id = w.warehouse_id
         JOIN users u ON mr.requested_by = u.user_id
         LEFT JOIN users a ON mr.approved_by = a.user_id
         LEFT JOIN request_items ri ON mr.request_id = ri.request_id
         LEFT JOIN spare_parts sp ON ri.part_id = sp.part_id
         ${role === 'MAINTENANCE_TECH' ? 'WHERE mr.requested_by = :userId' : ''}
         ORDER BY mr.request_id DESC`,
        {
          replacements: { userId: req.user.user_id },
          type: QueryTypes.SELECT
        }
      ),
      isLogistics
        ? sequelize.query(
            `SELECT po.*, s.supplier_code, s.supplier_name, w.warehouse_code, sp.part_number, sp.part_name,
                    (po.ordered_qty * po.unit_price) AS total_amount, u.full_name AS creator_name
             FROM purchase_orders po
             JOIN suppliers s ON po.supplier_id = s.supplier_id
             JOIN warehouses w ON po.warehouse_id = w.warehouse_id
             JOIN spare_parts sp ON po.part_id = sp.part_id
             JOIN users u ON po.created_by = u.user_id
             ORDER BY po.po_id DESC`,
            { type: QueryTypes.SELECT }
          )
        : Promise.resolve([]),
      isAdmin
        ? sequelize.query(
            `SELECT l.log_id, l.actor_user_id, l.module_name, l.warehouse_id, l.part_id,
                    l.action_type, l.activity_details, l.old_qty, l.new_qty, l.qty_delta,
                    l.storage_bin_snapshot, l.logged_at,
                    COALESCE(u.full_name, 'System Automation') AS actor_name,
                    COALESCE(u.username, 'system') AS actor_username,
                    COALESCE(u.role, 'SYSTEM') AS actor_role,
                    w.warehouse_code, sp.part_number, sp.part_name
             FROM inventory_audit_logs l
             LEFT JOIN users u ON l.actor_user_id = u.user_id
             LEFT JOIN warehouses w ON l.warehouse_id = w.warehouse_id
             LEFT JOIN spare_parts sp ON l.part_id = sp.part_id
             ORDER BY l.log_id DESC LIMIT 100`,
            { type: QueryTypes.SELECT }
          )
        : isLogistics
        ? sequelize.query(
            `SELECT l.log_id, l.actor_user_id, l.module_name, l.warehouse_id, l.part_id,
                    l.action_type, l.activity_details, l.old_qty, l.new_qty, l.qty_delta,
                    l.storage_bin_snapshot, l.logged_at,
                    COALESCE(u.full_name, 'System Automation') AS actor_name,
                    COALESCE(u.role, 'SYSTEM') AS actor_role,
                    w.warehouse_code, sp.part_number, sp.part_name
             FROM inventory_audit_logs l
             LEFT JOIN users u ON l.actor_user_id = u.user_id
             LEFT JOIN warehouses w ON l.warehouse_id = w.warehouse_id
             LEFT JOIN spare_parts sp ON l.part_id = sp.part_id
             WHERE l.module_name IN ('Inventory', 'Purchase Orders', 'Part Requests')
             ORDER BY l.log_id DESC LIMIT 50`,
            { type: QueryTypes.SELECT }
          )
        : Promise.resolve([]),
      isLogistics
        ? sequelize.query(
            `SELECT m.machine_code, m.machine_name, m.plant_section,
                    COUNT(DISTINCT mr.request_id) AS total_jobs,
                    COALESCE(SUM(ri.issued_qty - ri.returned_qty), 0) AS net_parts_consumed,
                    COALESCE(SUM((ri.issued_qty - ri.returned_qty) * sp.unit_cost), 0) AS maintenance_part_cost
             FROM machines m
             LEFT JOIN maintenance_requests mr ON m.machine_id = mr.machine_id
             LEFT JOIN request_items ri ON mr.request_id = ri.request_id
             LEFT JOIN spare_parts sp ON ri.part_id = sp.part_id
             GROUP BY m.machine_id, m.machine_code, m.machine_name, m.plant_section
             ORDER BY maintenance_part_cost DESC`,
            { type: QueryTypes.SELECT }
          )
        : Promise.resolve([]),
      isLogistics
        ? sequelize.query(
            `SELECT s.supplier_code, s.supplier_name, s.contact_person,
                    COUNT(po.po_id) AS total_orders,
                    COALESCE(SUM(po.ordered_qty), 0) AS total_units_ordered,
                    COALESCE(SUM(po.ordered_qty * po.unit_price), 0) AS total_spend
             FROM suppliers s
             LEFT JOIN purchase_orders po ON s.supplier_id = po.supplier_id
             GROUP BY s.supplier_id, s.supplier_code, s.supplier_name, s.contact_person
             ORDER BY total_spend DESC`,
            { type: QueryTypes.SELECT }
          )
        : Promise.resolve([]),
      isLogistics
        ? sequelize.query(
            `SELECT w.warehouse_code, w.warehouse_name, w.capacity_limit,
                    COUNT(wi.part_id) AS distinct_skus,
                    COALESCE(SUM(wi.current_qty), 0) AS total_physical_units,
                    COALESCE(SUM(wi.damaged_qty), 0) AS total_damaged_units,
                    COALESCE(SUM(wi.current_qty * sp.unit_cost), 0) AS total_inventory_value
             FROM warehouses w
             LEFT JOIN warehouse_inventory wi ON w.warehouse_id = wi.warehouse_id
             LEFT JOIN spare_parts sp ON wi.part_id = sp.part_id
             GROUP BY w.warehouse_id, w.warehouse_code, w.warehouse_name, w.capacity_limit
             ORDER BY w.warehouse_id`,
            { type: QueryTypes.SELECT }
          )
        : Promise.resolve([])
    ]);

    res.json({
      activeRole: role,
      activeUser: req.user,
      users,
      warehouses,
      suppliers,
      machines,
      parts,
      inventory,
      lowStock,
      requests,
      purchaseOrders,
      auditLogs,
      reports: {
        machineUsageReport,
        supplierSpendReport,
        warehouseValuationReport
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
};

// ============================================================================
// USER & ROLE MANAGEMENT (ADMIN) WITH EMAIL & PASSWORD VALIDATION
// ============================================================================

exports.createUserByAdmin = async (req, res) => {
  try {
    const username = sanitizeText(req.body.username);
    const full_name = sanitizeText(req.body.full_name);
    const email = sanitizeText(req.body.email).toLowerCase();
    const password = String(req.body.password || '');
    const role = sanitizeText(req.body.role);
    const assigned_warehouse_id = Number(req.body.assigned_warehouse_id || 1);

    if (!username || !full_name || !email || !password || !role) {
      return res.status(400).json({ error: 'All user account fields are required.' });
    }

    const usernameErr = validateUsername(username);
    if (usernameErr) return res.status(400).json({ error: usernameErr });

    const emailErr = validateEmail(email);
    if (emailErr) return res.status(400).json({ error: emailErr });

    const passwordErr = validatePassword(password);
    if (passwordErr) return res.status(400).json({ error: passwordErr });

    const existing = await sequelize.query(
      `SELECT username, email FROM users WHERE LOWER(email) = LOWER(:email) OR LOWER(username) = LOWER(:username) LIMIT 1`,
      { replacements: { email, username }, type: QueryTypes.SELECT }
    );
    if (existing.length > 0) {
      if (existing[0].email.toLowerCase() === email) {
        return res.status(409).json({ error: 'This email address is already registered to another user.' });
      }
      return res.status(409).json({ error: 'This username is already taken.' });
    }

    const password_hash = hashPassword(password);
    await sequelize.query(
      `INSERT INTO users (username, password_hash, full_name, email, role, assigned_warehouse_id, is_active)
       VALUES (:username, :password_hash, :full_name, :email, :role, :assigned_warehouse_id, TRUE)`,
      {
        replacements: {
          username,
          password_hash,
          full_name,
          email,
          role,
          assigned_warehouse_id
        },
        type: QueryTypes.INSERT
      }
    );

    await logActivity(
      req.user.user_id,
      'Users',
      'Added User',
      `Created user '${username}' (${email}) with role ${role}`,
      assigned_warehouse_id,
      null
    );

    res.json({ message: `User account '${username}' created.` });
  } catch (err) {
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

exports.updateUserAccess = async (req, res) => {
  try {
    const { user_id } = req.params;
    const { role, is_active, assigned_warehouse_id } = req.body;

    if (Number(user_id) === req.user.user_id && is_active === false) {
      return res.status(400).json({ error: 'Cannot deactivate your own active session.' });
    }

    await sequelize.query(
      `UPDATE users
       SET role = :role, is_active = :is_active, assigned_warehouse_id = :assigned_warehouse_id
       WHERE user_id = :user_id`,
      {
        replacements: {
          role,
          is_active: Boolean(is_active),
          assigned_warehouse_id: assigned_warehouse_id || 1,
          user_id: Number(user_id)
        },
        type: QueryTypes.UPDATE
      }
    );

    await logActivity(
      req.user.user_id,
      'Users',
      is_active ? 'Activated User' : 'Deactivated User',
      `Set user #${user_id} status to ${is_active ? 'ACTIVE' : 'INACTIVE'} (Role: ${role})`,
      assigned_warehouse_id || 1,
      null
    );

    res.json({ message: `User #${user_id} updated.` });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

// ============================================================================
// SPARE PARTS CATALOG CRUD WITH VALIDATION
// ============================================================================

exports.createSparePart = async (req, res) => {
  try {
    const part_number = sanitizeText(req.body.part_number).toUpperCase();
    const part_name = sanitizeText(req.body.part_name);
    const category = sanitizeText(req.body.category);
    const manufacturer = sanitizeText(req.body.manufacturer);
    const unit_of_measure = sanitizeText(req.body.unit_of_measure || 'pcs');
    const unit_cost = Number(req.body.unit_cost);
    const reorder_level = Number(req.body.reorder_level);
    const min_stock_level = Number(req.body.min_stock_level);

    if (!/^[A-Z0-9\-_]{3,40}$/.test(part_number)) {
      return res.status(400).json({ error: 'Part number must be 3–40 characters using letters, numbers, or hyphens (e.g. BRG-1001).' });
    }
    if (isNaN(unit_cost) || unit_cost <= 0) {
      return res.status(400).json({ error: 'Unit cost must be greater than 0.' });
    }
    if (isNaN(min_stock_level) || min_stock_level < 1) {
      return res.status(400).json({ error: 'Minimum stock level must be at least 1.' });
    }
    if (isNaN(reorder_level) || reorder_level <= min_stock_level) {
      return res.status(400).json({ error: 'Reorder level must be strictly greater than minimum stock level.' });
    }

    const dupPart = await sequelize.query(
      `SELECT part_id FROM spare_parts WHERE UPPER(part_number) = :part_number LIMIT 1`,
      { replacements: { part_number }, type: QueryTypes.SELECT }
    );
    if (dupPart.length > 0) {
      return res.status(409).json({ error: `Part number '${part_number}' already exists in the catalog.` });
    }

    const [partId] = await sequelize.query(
      `INSERT INTO spare_parts (part_number, part_name, category, manufacturer, unit_of_measure, unit_cost, reorder_level, min_stock_level)
       VALUES (:part_number, :part_name, :category, :manufacturer, :unit_of_measure, :unit_cost, :reorder_level, :min_stock_level)`,
      {
        replacements: {
          part_number,
          part_name,
          category,
          manufacturer,
          unit_of_measure,
          unit_cost,
          reorder_level,
          min_stock_level
        },
        type: QueryTypes.INSERT
      }
    );

    await logActivity(
      req.user.user_id,
      'Spare Parts',
      'Added Part',
      `Registered ${part_number} (${part_name}) in catalog`,
      null,
      partId
    );

    res.json({ message: `Spare part ${part_number} added.` });
  } catch (err) {
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

exports.updateSparePart = async (req, res) => {
  try {
    const { part_id } = req.params;
    const part_name = sanitizeText(req.body.part_name);
    const category = sanitizeText(req.body.category);
    const manufacturer = sanitizeText(req.body.manufacturer);
    const unit_cost = Number(req.body.unit_cost);
    const reorder_level = Number(req.body.reorder_level);
    const min_stock_level = Number(req.body.min_stock_level);

    if (isNaN(unit_cost) || unit_cost <= 0) {
      return res.status(400).json({ error: 'Unit cost must be greater than 0.' });
    }
    if (isNaN(min_stock_level) || min_stock_level < 1) {
      return res.status(400).json({ error: 'Minimum stock level must be at least 1.' });
    }
    if (isNaN(reorder_level) || reorder_level <= min_stock_level) {
      return res.status(400).json({ error: 'Reorder level must be greater than minimum stock level.' });
    }

    await sequelize.query(
      `UPDATE spare_parts
       SET part_name = :part_name, category = :category, manufacturer = :manufacturer,
           unit_cost = :unit_cost, reorder_level = :reorder_level, min_stock_level = :min_stock_level
       WHERE part_id = :part_id`,
      {
        replacements: {
          part_name,
          category,
          manufacturer,
          unit_cost,
          reorder_level,
          min_stock_level,
          part_id: Number(part_id)
        },
        type: QueryTypes.UPDATE
      }
    );

    await logActivity(
      req.user.user_id,
      'Spare Parts',
      'Updated Part',
      `Updated details for ${part_name} (Cost: PHP ${unit_cost}, Reorder: ${reorder_level})`,
      null,
      Number(part_id)
    );

    res.json({ message: `Spare part #${part_id} updated.` });
  } catch (err) {
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

exports.deleteSparePart = async (req, res) => {
  try {
    const { part_id } = req.params;
    await sequelize.query('DELETE FROM spare_parts WHERE part_id = :part_id', {
      replacements: { part_id: Number(part_id) },
      type: QueryTypes.DELETE
    });

    await logActivity(
      req.user.user_id,
      'Spare Parts',
      'Deleted Part',
      `Deleted spare part #${part_id} from catalog`,
      null,
      null
    );

    res.json({ message: `Spare part #${part_id} removed.` });
  } catch (err) {
    if (err.original && (err.original.errno === 1451 || err.original.code === 'ER_ROW_IS_REFERENCED_2')) {
      return res.status(409).json({
        error: 'Cannot delete this spare part because it is referenced by existing warehouse inventory, purchase orders, or requests.'
      });
    }
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

// ============================================================================
// WAREHOUSE INVENTORY & STORAGE BIN MANAGEMENT WITH VALIDATION
// ============================================================================

exports.upsertWarehouseBinStock = async (req, res) => {
  try {
    const warehouse_id = Number(req.body.warehouse_id);
    const part_id = Number(req.body.part_id);
    const storage_bin_location = sanitizeText(req.body.storage_bin_location);
    const current_qty = Number(req.body.current_qty);
    const reserved_qty = Number(req.body.reserved_qty || 0);
    const damaged_qty = Number(req.body.damaged_qty || 0);

    if (!storage_bin_location || storage_bin_location.length < 2) {
      return res.status(400).json({ error: 'Valid storage bin location code is required.' });
    }
    if (current_qty < 0 || reserved_qty < 0 || damaged_qty < 0) {
      return res.status(400).json({ error: 'Stock quantities cannot be negative.' });
    }
    if (reserved_qty > current_qty) {
      return res.status(400).json({ error: 'Reserved quantity cannot exceed physical current quantity.' });
    }

    await sequelize.query(`SET @current_actor_id = :actorId`, {
      replacements: { actorId: req.user.user_id }
    });

    await sequelize.query(
      `INSERT INTO warehouse_inventory (warehouse_id, part_id, storage_bin_location, current_qty, reserved_qty, damaged_qty)
       VALUES (:warehouse_id, :part_id, :storage_bin_location, :current_qty, :reserved_qty, :damaged_qty)
       ON DUPLICATE KEY UPDATE
         storage_bin_location = VALUES(storage_bin_location),
         current_qty = VALUES(current_qty),
         reserved_qty = VALUES(reserved_qty),
         damaged_qty = VALUES(damaged_qty)`,
      {
        replacements: {
          warehouse_id,
          part_id,
          storage_bin_location,
          current_qty,
          reserved_qty,
          damaged_qty
        },
        type: QueryTypes.INSERT
      }
    );

    await logActivity(
      req.user.user_id,
      'Inventory',
      'Updated Bin / Stock',
      `Updated WH #${warehouse_id} Part #${part_id} at bin ${storage_bin_location} (Qty: ${current_qty}, Damaged: ${damaged_qty})`,
      warehouse_id,
      part_id
    );

    res.json({ message: 'Warehouse bin and stock quantities updated.' });
  } catch (err) {
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

exports.transferWarehouseStock = async (req, res) => {
  try {
    const part_id = Number(req.body.part_id);
    const from_warehouse_id = Number(req.body.from_warehouse_id);
    const to_warehouse_id = Number(req.body.to_warehouse_id);
    const transfer_qty = Number(req.body.transfer_qty);
    const target_bin = sanitizeText(req.body.target_bin || 'TRANSFER-BIN-01');

    if (from_warehouse_id === to_warehouse_id) {
      return res.status(400).json({ error: 'Source and destination warehouses must be different.' });
    }
    if (isNaN(transfer_qty) || transfer_qty <= 0) {
      return res.status(400).json({ error: 'Transfer quantity must be at least 1.' });
    }

    await sequelize.query(`SET @current_actor_id = :actorId`, {
      replacements: { actorId: req.user.user_id }
    });

    await sequelize.query(
      'CALL sp_transfer_warehouse_stock(:part_id, :from_warehouse_id, :to_warehouse_id, :transfer_qty, :target_bin)',
      {
        replacements: {
          part_id,
          from_warehouse_id,
          to_warehouse_id,
          transfer_qty,
          target_bin
        }
      }
    );

    await logActivity(
      req.user.user_id,
      'Inventory',
      'Transferred Stock',
      `Transferred ${transfer_qty} units of Part #${part_id} from WH #${from_warehouse_id} to WH #${to_warehouse_id} (${target_bin})`,
      to_warehouse_id,
      part_id
    );

    res.json({ message: 'Stock transfer completed.' });
  } catch (err) {
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

// ============================================================================
// MAINTENANCE REQUESTS, APPROVALS, RELEASE & RETURNS
// ============================================================================

exports.createMaintenanceRequest = async (req, res) => {
  const t = await sequelize.transaction();
  try {
    const machine_id = Number(req.body.machine_id);
    const warehouse_id = Number(req.body.warehouse_id);
    const part_id = Number(req.body.part_id);
    const requested_qty = Number(req.body.requested_qty);
    const priority = sanitizeText(req.body.priority);
    const maintenance_task_desc = sanitizeText(req.body.maintenance_task_desc);
    const usage_notes = sanitizeText(req.body.usage_notes || 'Maintenance task');

    if (isNaN(requested_qty) || requested_qty <= 0) {
      await t.rollback();
      return res.status(400).json({ error: 'Requested quantity must be at least 1.' });
    }
    if (!maintenance_task_desc || maintenance_task_desc.length < 5) {
      await t.rollback();
      return res.status(400).json({ error: 'Please provide a clear maintenance task description (at least 5 characters).' });
    }

    const request_number = 'REQ-' + Date.now().toString().slice(-6);

    const [result] = await sequelize.query(
      `INSERT INTO maintenance_requests (request_number, machine_id, warehouse_id, requested_by, maintenance_task_desc, priority)
       VALUES (:request_number, :machine_id, :warehouse_id, :requested_by, :maintenance_task_desc, :priority)`,
      {
        replacements: {
          request_number,
          machine_id,
          warehouse_id,
          requested_by: req.user.user_id,
          maintenance_task_desc,
          priority
        },
        type: QueryTypes.INSERT,
        transaction: t
      }
    );

    await sequelize.query(
      `INSERT INTO request_items (request_id, part_id, requested_qty, usage_notes)
       VALUES (:request_id, :part_id, :requested_qty, :usage_notes)`,
      {
        replacements: {
          request_id: result,
          part_id,
          requested_qty,
          usage_notes
        },
        type: QueryTypes.INSERT,
        transaction: t
      }
    );

    await t.commit();
    res.json({ message: `Part request ${request_number} submitted.` });
  } catch (err) {
    await t.rollback();
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

exports.updateRequestStatus = async (req, res) => {
  try {
    const { request_id, status } = req.body;
    if (!['APPROVED', 'REJECTED'].includes(status)) {
      return res.status(400).json({ error: 'Invalid status.' });
    }
    await sequelize.query(`SET @current_actor_id = :actorId`, {
      replacements: { actorId: req.user.user_id }
    });

    await sequelize.query(
      `UPDATE maintenance_requests SET status = :status, approved_by = :approved_by WHERE request_id = :request_id`,
      {
        replacements: { status, approved_by: req.user.user_id, request_id: Number(request_id) },
        type: QueryTypes.UPDATE
      }
    );
    res.json({ message: `Request #${request_id} marked as ${status}.` });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

exports.releaseApprovedStock = async (req, res) => {
  try {
    const { request_id } = req.body;
    await sequelize.query(`SET @current_actor_id = :actorId`, {
      replacements: { actorId: req.user.user_id }
    });

    await sequelize.query('CALL sp_release_maintenance_stock(:request_id)', {
      replacements: { request_id: Number(request_id) }
    });
    res.json({ message: `Stock released for Request #${request_id}.` });
  } catch (err) {
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

exports.returnUnusedParts = async (req, res) => {
  const t = await sequelize.transaction();
  try {
    const { request_id, part_id, warehouse_id, return_qty } = req.body;
    const qty = Number(return_qty);
    if (!qty || qty <= 0) {
      await t.rollback();
      return res.status(400).json({ error: 'Return quantity must be greater than zero.' });
    }

    await sequelize.query(
      `UPDATE request_items
       SET returned_qty = returned_qty + :qty
       WHERE request_id = :request_id AND part_id = :part_id AND (issued_qty - returned_qty) >= :qty`,
      {
        replacements: { qty, request_id: Number(request_id), part_id: Number(part_id) },
        type: QueryTypes.UPDATE,
        transaction: t
      }
    );

    await sequelize.query(
      `UPDATE warehouse_inventory
       SET current_qty = current_qty + :qty
       WHERE warehouse_id = :warehouse_id AND part_id = :part_id`,
      {
        replacements: { qty, warehouse_id: Number(warehouse_id), part_id: Number(part_id) },
        type: QueryTypes.UPDATE,
        transaction: t
      }
    );

    await t.commit();

    await logActivity(
      req.user.user_id,
      'Part Requests',
      'Returned Unused Part',
      `Returned ${qty} unused unit(s) from Request #${request_id} back to WH #${warehouse_id}`,
      Number(warehouse_id),
      Number(part_id)
    );

    res.json({ message: `Returned ${qty} unused unit(s) to warehouse stock.` });
  } catch (err) {
    await t.rollback();
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

// ============================================================================
// SUPPLIERS, PURCHASE ORDERS, WAREHOUSES & MACHINES WITH VALIDATION
// ============================================================================

exports.createSupplier = async (req, res) => {
  try {
    const supplier_code = sanitizeText(req.body.supplier_code).toUpperCase();
    const supplier_name = sanitizeText(req.body.supplier_name);
    const contact_person = sanitizeText(req.body.contact_person);
    const email = sanitizeText(req.body.email).toLowerCase();
    const phone = sanitizeText(req.body.phone);

    if (!/^[A-Z0-9\-_]{3,20}$/.test(supplier_code)) {
      return res.status(400).json({ error: 'Supplier code must be 3–20 characters (letters, numbers, hyphens).' });
    }
    const emailErr = validateEmail(email);
    if (emailErr) return res.status(400).json({ error: emailErr });

    const phoneErr = validatePhone(phone);
    if (phoneErr) return res.status(400).json({ error: phoneErr });

    const dupSup = await sequelize.query(
      `SELECT supplier_code, email FROM suppliers WHERE UPPER(supplier_code) = :supplier_code OR LOWER(email) = :email LIMIT 1`,
      { replacements: { supplier_code, email }, type: QueryTypes.SELECT }
    );
    if (dupSup.length > 0) {
      if (dupSup[0].email.toLowerCase() === email) {
        return res.status(409).json({ error: 'A supplier with this email address is already registered.' });
      }
      return res.status(409).json({ error: `Supplier code '${supplier_code}' already exists.` });
    }

    await sequelize.query(
      `INSERT INTO suppliers (supplier_code, supplier_name, contact_person, email, phone)
       VALUES (:supplier_code, :supplier_name, :contact_person, :email, :phone)`,
      {
        replacements: { supplier_code, supplier_name, contact_person, email, phone },
        type: QueryTypes.INSERT
      }
    );

    await logActivity(
      req.user.user_id,
      'Suppliers',
      'Added Supplier',
      `Registered supplier ${supplier_code} (${supplier_name})`,
      null,
      null
    );

    res.json({ message: `Supplier ${supplier_name} added.` });
  } catch (err) {
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

exports.createPurchaseOrder = async (req, res) => {
  try {
    const supplier_id = Number(req.body.supplier_id);
    const warehouse_id = Number(req.body.warehouse_id);
    const part_id = Number(req.body.part_id);
    const ordered_qty = Number(req.body.ordered_qty);
    const unit_price = Number(req.body.unit_price);

    if (isNaN(ordered_qty) || ordered_qty <= 0) {
      return res.status(400).json({ error: 'Ordered quantity must be greater than 0.' });
    }
    if (isNaN(unit_price) || unit_price <= 0) {
      return res.status(400).json({ error: 'Unit price must be greater than 0.' });
    }

    const po_number = 'PO-' + Date.now().toString().slice(-6);
    await sequelize.query(
      `INSERT INTO purchase_orders (po_number, supplier_id, warehouse_id, part_id, ordered_qty, unit_price, created_by)
       VALUES (:po_number, :supplier_id, :warehouse_id, :part_id, :ordered_qty, :unit_price, :created_by)`,
      {
        replacements: {
          po_number,
          supplier_id,
          warehouse_id,
          part_id,
          ordered_qty,
          unit_price,
          created_by: req.user.user_id
        },
        type: QueryTypes.INSERT
      }
    );
    res.json({ message: `Purchase Order ${po_number} created.` });
  } catch (err) {
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

exports.receivePurchaseOrder = async (req, res) => {
  try {
    const { po_id } = req.body;
    await sequelize.query(`SET @current_actor_id = :actorId`, {
      replacements: { actorId: req.user.user_id }
    });

    await sequelize.query(
      `UPDATE purchase_orders SET po_status = 'RECEIVED', received_at = NOW() WHERE po_id = :po_id`,
      {
        replacements: { po_id: Number(po_id) },
        type: QueryTypes.UPDATE
      }
    );
    res.json({ message: `Purchase Order #${po_id} marked as received.` });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

exports.createWarehouse = async (req, res) => {
  try {
    const warehouse_code = sanitizeText(req.body.warehouse_code).toUpperCase();
    const warehouse_name = sanitizeText(req.body.warehouse_name);
    const location_address = sanitizeText(req.body.location_address);
    const capacity_limit = Number(req.body.capacity_limit);

    if (!/^[A-Z0-9\-_]{3,20}$/.test(warehouse_code)) {
      return res.status(400).json({ error: 'Warehouse code must be 3–20 characters (letters, numbers, hyphens).' });
    }
    if (isNaN(capacity_limit) || capacity_limit < 100) {
      return res.status(400).json({ error: 'Warehouse capacity limit must be at least 100 units.' });
    }

    const dupWh = await sequelize.query(
      `SELECT warehouse_id FROM warehouses WHERE UPPER(warehouse_code) = :warehouse_code LIMIT 1`,
      { replacements: { warehouse_code }, type: QueryTypes.SELECT }
    );
    if (dupWh.length > 0) {
      return res.status(409).json({ error: `Warehouse code '${warehouse_code}' already exists.` });
    }

    const [whId] = await sequelize.query(
      `INSERT INTO warehouses (warehouse_code, warehouse_name, location_address, capacity_limit)
       VALUES (:warehouse_code, :warehouse_name, :location_address, :capacity_limit)`,
      {
        replacements: { warehouse_code, warehouse_name, location_address, capacity_limit },
        type: QueryTypes.INSERT
      }
    );

    await logActivity(
      req.user.user_id,
      'Warehouses',
      'Added Warehouse',
      `Added warehouse branch ${warehouse_code} (${warehouse_name})`,
      whId,
      null
    );

    res.json({ message: `Warehouse ${warehouse_code} added.` });
  } catch (err) {
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

exports.createMachine = async (req, res) => {
  try {
    const machine_code = sanitizeText(req.body.machine_code).toUpperCase();
    const machine_name = sanitizeText(req.body.machine_name);
    const plant_section = sanitizeText(req.body.plant_section);
    const operational_status = sanitizeText(req.body.operational_status || 'OPERATIONAL');

    if (!/^[A-Z0-9\-_]{3,30}$/.test(machine_code)) {
      return res.status(400).json({ error: 'Machine code must be 3–30 characters (letters, numbers, hyphens).' });
    }

    const dupMc = await sequelize.query(
      `SELECT machine_id FROM machines WHERE UPPER(machine_code) = :machine_code LIMIT 1`,
      { replacements: { machine_code }, type: QueryTypes.SELECT }
    );
    if (dupMc.length > 0) {
      return res.status(409).json({ error: `Machine code '${machine_code}' already exists.` });
    }

    await sequelize.query(
      `INSERT INTO machines (machine_code, machine_name, plant_section, operational_status)
       VALUES (:machine_code, :machine_name, :plant_section, :operational_status)`,
      {
        replacements: {
          machine_code,
          machine_name,
          plant_section,
          operational_status
        },
        type: QueryTypes.INSERT
      }
    );

    await logActivity(
      req.user.user_id,
      'Machines',
      'Added Machine',
      `Added machine ${machine_code} (${machine_name}) in ${plant_section}`,
      null,
      null
    );

    res.json({ message: `Machine ${machine_code} added.` });
  } catch (err) {
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};

exports.updateMachineStatus = async (req, res) => {
  try {
    const { machine_id } = req.params;
    const { operational_status } = req.body;
    await sequelize.query(
      `UPDATE machines SET operational_status = :operational_status WHERE machine_id = :machine_id`,
      {
        replacements: { operational_status, machine_id: Number(machine_id) },
        type: QueryTypes.UPDATE
      }
    );

    await logActivity(
      req.user.user_id,
      'Machines',
      'Updated Machine Status',
      `Changed Machine #${machine_id} status to ${operational_status}`,
      null,
      null
    );

    res.json({ message: `Machine #${machine_id} status updated.` });
  } catch (err) {
    res.status(400).json({ error: err.original?.sqlMessage || err.message });
  }
};