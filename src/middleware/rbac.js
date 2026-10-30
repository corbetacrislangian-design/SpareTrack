const crypto = require('crypto');
const sequelize = require('../config/db');
const { QueryTypes } = require('sequelize');

// Server-only cryptographic secret (regenerated on server boot if not in .env)
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

// Server-side authoritative session registry (cannot be accessed or forged from browser)
const activeSessions = new Map();

function signToken(payloadStr) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(payloadStr).digest('hex');
}

function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    const key = parts.shift().trim();
    const value = decodeURI(parts.join('='));
    if (key) list[key] = value;
  });
  return list;
}

function createSession(user, req, res) {
  const sid = crypto.randomBytes(24).toString('hex');
  const expiresAt = Date.now() + SESSION_TTL_MS;
  const payload = `${sid}.${user.user_id}.${user.role}.${expiresAt}`;
  const signature = signToken(payload);
  const fullToken = `${payload}.${signature}`;

  activeSessions.set(sid, {
    sid,
    user_id: Number(user.user_id),
    username: user.username,
    full_name: user.full_name,
    role: user.role,
    userAgent: req.headers['user-agent'] || 'unknown',
    expiresAt
  });

  // Set HttpOnly cookie so browser DevTools Console cannot read or modify it
  res.setHeader(
    'Set-Cookie',
    `sparetrack_sid=${fullToken}; HttpOnly; Path=/; SameSite=Strict; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
  );

  return fullToken;
}

function destroySession(req, res) {
  const cookies = parseCookies(req.headers.cookie);
  const bearer = req.headers.authorization?.startsWith('Bearer ')
    ? req.headers.authorization.slice(7).trim()
    : null;
  const rawToken = cookies.sparetrack_sid || bearer;

  if (rawToken) {
    const parts = rawToken.split('.');
    if (parts.length === 5) {
      activeSessions.delete(parts[0]);
    }
  }

  if (res) {
    res.setHeader('Set-Cookie', 'sparetrack_sid=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0');
  }
}

function verifyTokenString(rawToken) {
  if (!rawToken || typeof rawToken !== 'string') return null;
  const parts = rawToken.split('.');
  if (parts.length !== 5) return null;

  const [sid, uidStr, role, expStr, providedSig] = parts;
  const payload = `${sid}.${uidStr}.${role}.${expStr}`;
  const expectedSig = signToken(payload);

  const bufProvided = Buffer.from(providedSig, 'hex');
  const bufExpected = Buffer.from(expectedSig, 'hex');
  if (bufProvided.length !== bufExpected.length || !crypto.timingSafeEqual(bufProvided, bufExpected)) {
    return null;
  }

  const session = activeSessions.get(sid);
  if (!session) return null;

  if (Date.now() > session.expiresAt || Date.now() > Number(expStr)) {
    activeSessions.delete(sid);
    return null;
  }

  if (session.user_id !== Number(uidStr) || session.role !== role) {
    return null;
  }

  return session;
}

async function logSecurityIncident(userId, actionType, details) {
  try {
    await sequelize.query(
      `CALL sp_record_audit_log(:userId, 'Security', :actionType, :details, NULL, NULL)`,
      {
        replacements: {
          userId: userId || null,
          actionType,
          details: String(details).slice(0, 250)
        }
      }
    );
  } catch (e) {
    // Ignore if audit proc not yet initialized
  }
}

const authorizeRoles = (...allowedRoles) => {
  return async (req, res, next) => {
    try {
      const cookies = parseCookies(req.headers.cookie);
      const cookieToken = cookies.sparetrack_sid;
      const bearerToken = req.headers.authorization?.startsWith('Bearer ')
        ? req.headers.authorization.slice(7).trim()
        : null;

      // Require valid cryptographic session token from HttpOnly cookie or Bearer header
      const tokenToVerify = cookieToken || bearerToken;
      if (!tokenToVerify) {
        return res.status(401).json({ error: 'Authentication required. Please sign in.' });
      }

      // If both cookie and bearer token are sent, they must match (detects DevTools token swapping)
      if (cookieToken && bearerToken && cookieToken !== bearerToken) {
        destroySession(req, res);
        await logSecurityIncident(null, 'Token Tampering Blocked', 'Mismatched HttpOnly cookie and Bearer token detected');
        return res.status(401).json({ error: 'Security Alert: Session token mismatch detected. Logged out.' });
      }

      const session = verifyTokenString(tokenToVerify);
      if (!session) {
        destroySession(req, res);
        return res.status(401).json({ error: 'Session expired or invalid signature. Please sign in again.' });
      }

      // Detect if user opened DevTools -> LocalStorage and edited user_id or role
      const clientClaimedUid = req.headers['x-client-uid'];
      const clientClaimedRole = req.headers['x-client-role'];
      if (
        (clientClaimedUid && Number(clientClaimedUid) !== session.user_id) ||
        (clientClaimedRole && clientClaimedRole !== session.role)
      ) {
        destroySession(req, res);
        await logSecurityIncident(
          session.user_id,
          'Tampering Blocked',
          `User '${session.username}' (${session.role}) attempted DevTools session tampering (claimed UID:${clientClaimedUid}, Role:${clientClaimedRole})`
        );
        return res.status(401).json({
          error: 'Security Violation: Client storage tampering detected. Your session has been terminated and logged.'
        });
      }

      // Re-verify live account status and role directly from Cloud MySQL Database
      const users = await sequelize.query(
        'SELECT user_id, username, full_name, role, assigned_warehouse_id, is_active FROM users WHERE user_id = :userId LIMIT 1',
        {
          replacements: { userId: session.user_id },
          type: QueryTypes.SELECT
        }
      );

      if (!users.length || !users[0].is_active) {
        destroySession(req, res);
        return res.status(403).json({ error: 'Account deactivated or removed by Administrator.' });
      }

      const currentUser = users[0];
      // Update session role if Admin changed it live in database
      session.role = currentUser.role;

      if (!allowedRoles.includes(currentUser.role)) {
        await logSecurityIncident(
          currentUser.user_id,
          'Unauthorized Access Blocked',
          `Role '${currentUser.role}' attempted restricted action on ${req.method} ${req.originalUrl}`
        );
        return res.status(403).json({
          error: `Access Denied: Your role (${currentUser.role}) is not authorized to perform this action.`
        });
      }

      req.user = currentUser;
      next();
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  };
};

module.exports = {
  authorizeRoles,
  createSession,
  destroySession
};