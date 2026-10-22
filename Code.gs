// ======================================================================
//  Study LEAP - Google Apps Script  (Code.gs)
//  VERSION 4 - token-protected uploads, validated files, no public OTP
// ======================================================================
//
//  SECURITY MODEL (v4)
//  - The OTP is now generated, sent and verified by the Cloudflare Worker
//    (POST /otp/send and /otp/verify). This script NEVER sends OTPs.
//  - A successful OTP check gives the browser a signed token
//    (phone.expiry.signature). Every upload and summary request must carry
//    a valid, unexpired token; the phone number comes from the token, not
//    from the browser.
//  - Files are checked server-side: allowed document types only, PDF/JPG/
//    PNG/WebP only (verified by file signature), max 10 MB each.
//
//  SETUP
//  1. Project Settings (gear) > Script Properties > add
//         UPLOAD_SECRET = <same value as the Worker secret OTP_SECRET>
//     (use a long random string, at least 32 characters)
//  2. Deploy > Manage deployments > Edit (pencil) > Version: New version >
//     Deploy   (keeps the same /exec URL)
//  3. Run testToken(), then testUpload() once to authorise Drive/Gmail.
//
// ======================================================================

const DRIVE_FOLDER_NAME = "Study LEAP \u2013 Loan Documents";
const NOTIFY_EMAIL      = "studyleapbnl@gmail.com";

const ALLOWED_DOC_KEYS = ['aadhaar', 'pan', 'tenth', 'twelfth', 'grad', 'admit', 'income', 'bank', 'photo', 'passport', 'gre', 'other'];
const ALLOWED_MIME     = { 'application/pdf': 'pdf', 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };
const MAX_FILE_BYTES         = 10 * 1024 * 1024;  // 10 MB per file
const MAX_UPLOADS_PER_HOUR   = 40;                // per verified phone number
const MAX_SUMMARIES_PER_HOUR = 3;                 // per verified phone number

// --- doGet: status only (no actions are exposed) -----------------------
function doGet(e) {
  return jsonOut({ status: 'Study LEAP API v4 running' });
}

// --- doPost: uploads + summary (token required) ------------------------
function doPost(e) {
  try {
    let data;
    if (e.parameter && e.parameter.data)        data = JSON.parse(e.parameter.data);   // form POST from browser
    else if (e.postData && e.postData.contents) data = JSON.parse(e.postData.contents);
    else                                        data = e.parameter || {};

    let result;
    if      (data.action === 'uploadFile')  result = handleUploadFile(data);
    else if (data.action === 'sendSummary') result = handleSendSummary(data);
    else throw new Error('Unknown action');
    return jsonOut(result);
  } catch (err) {
    Logger.log('doPost ERROR: ' + err.message);
    return jsonOut({ ok: false, error: err.message });
  }
}

// --- TOKEN + VALIDATION HELPERS ---------------------------------------
function getSecret_() {
  const s = PropertiesService.getScriptProperties().getProperty('UPLOAD_SECRET');
  if (!s || s.length < 16) throw new Error('Upload service not configured');
  return s;
}
function hmacHex_(secret, msg) {
  const sig = Utilities.computeHmacSha256Signature(msg, secret);
  return sig.map(function (b) { return ('0' + ((b + 256) % 256).toString(16)).slice(-2); }).join('');
}
function safeEq_(a, b) {
  if (a.length !== b.length) return false;
  var d = 0;
  for (var i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}
// Returns the verified 10-digit phone number or throws.
function verifyToken_(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('Mobile number not verified');
  const phone = parts[0], exp = Number(parts[1]);
  if (!/^[6-9]\d{9}$/.test(phone) || !exp) throw new Error('Mobile number not verified');
  if (Date.now() > exp) throw new Error('Verification expired. Please verify your mobile number again.');
  if (!safeEq_(hmacHex_(getSecret_(), phone + '.' + parts[1]), parts[2])) throw new Error('Mobile number not verified');
  return phone;
}
function bump_(key, max, ttlSec) {
  const cache = CacheService.getScriptCache();
  const n = Number(cache.get(key) || 0) + 1;
  if (n > max) throw new Error('Too many requests. Please try again later.');
  cache.put(key, String(n), ttlSec);
}
function sniffMime_(bytes) {
  function b(i) { return bytes[i] === undefined ? -1 : (bytes[i] + 256) % 256; }
  if (b(0) === 0x25 && b(1) === 0x50 && b(2) === 0x44 && b(3) === 0x46) return 'application/pdf';
  if (b(0) === 0xFF && b(1) === 0xD8 && b(2) === 0xFF) return 'image/jpeg';
  if (b(0) === 0x89 && b(1) === 0x50 && b(2) === 0x4E && b(3) === 0x47) return 'image/png';
  if (b(0) === 0x52 && b(1) === 0x49 && b(2) === 0x46 && b(3) === 0x46 &&
      b(8) === 0x57 && b(9) === 0x45 && b(10) === 0x42 && b(11) === 0x50) return 'image/webp';
  return '';
}
function clean_(v, max) {
  return String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f<>]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}
function esc_(v) {
  return String(v == null ? '' : v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function cleanName_(name, ext) {
  var base = String(name || 'document').split(/[\\\/]/).pop().replace(/\.[^.]*$/, '')
    .replace(/[^A-Za-z0-9._ -]/g, '_').slice(0, 60) || 'document';
  return base + '.' + ext;
}
function sanitizeInfo_(si, phone) {
  si = si || {};
  const email = clean_(si.email, 120);
  return {
    name: clean_(si.name, 80) || 'Unknown',
    phone: phone,                                           // from the verified token, never from the browser
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : '',
    course: clean_(si.course, 120), college: clean_(si.college, 120), amount: clean_(si.amount, 40),
    courseStartDate: clean_(si.courseStartDate, 30), bank: clean_(si.bank, 60),
    coName: clean_(si.coName, 80), coRelation: clean_(si.coRelation, 40),
    coOccupation: clean_(si.coOccupation, 60), coIncome: clean_(si.coIncome, 40)
  };
}

// --- UPLOAD FILE ------------------------------------------------------
function handleUploadFile(data) {
  const phone = verifyToken_(data.token);
  if (!data.data || typeof data.data !== 'string') throw new Error('No file data in request');
  if (ALLOWED_DOC_KEYS.indexOf(data.docKey) < 0)   throw new Error('Unknown document type');
  if (data.data.length > Math.ceil(MAX_FILE_BYTES * 4 / 3) + 16) throw new Error('File too large (max 10 MB)');
  bump_('up:' + phone, MAX_UPLOADS_PER_HOUR, 3600);

  const bytes = Utilities.base64Decode(data.data);
  if (bytes.length > MAX_FILE_BYTES) throw new Error('File too large (max 10 MB)');
  const real = sniffMime_(bytes);
  if (!real || !ALLOWED_MIME[real]) throw new Error('Only PDF, JPG, PNG or WebP files are accepted');

  const si     = sanitizeInfo_(data.studentInfo, phone);
  const folder = getOrCreateFolder(si);
  const name   = data.docKey + '_' + cleanName_(data.fileName, ALLOWED_MIME[real]);
  const file   = folder.createFile(Utilities.newBlob(bytes, real, name));
  Logger.log('File saved: ' + file.getName() + ' (' + data.docKey + ') for ***' + phone.slice(-4));
  return { ok: true, name: name };
}

// --- SEND SUMMARY EMAIL -----------------------------------------------
function handleSendSummary(data) {
  const phone = verifyToken_(data.token);              // must have passed WhatsApp OTP
  bump_('sum:' + phone, MAX_SUMMARIES_PER_HOUR, 3600);
  const si   = sanitizeInfo_(data.studentInfo, phone);
  const uploaded = (Array.isArray(data.docsUploaded) ? data.docsUploaded : [])
    .filter(function (k) { return ALLOWED_DOC_KEYS.indexOf(k) >= 0; });
  data = { docsUploaded: uploaded };
  const docs = uploaded.join(', ');

  const rootFolder = getOrCreateRootFolder();
  const folderUrl  = rootFolder.getUrl();

  // ── Team notification email (detailed) ──
  GmailApp.sendEmail(NOTIFY_EMAIL,
    '📄 New Docs – ' + si.name + ' | ' + si.phone,
    'New document submission!\n\n' +
    '── STUDENT ──\n' +
    'Name:         ' + (si.name    || '') + '\n' +
    'Phone:        +91 ' + (si.phone || '') + '\n' +
    'Email:        ' + (si.email   || '') + '\n' +
    'Course:       ' + (si.course  || '') + '\n' +
    'College:      ' + (si.college || '') + '\n' +
    'Start Date:   ' + (si.courseStartDate || 'Not provided') + '\n' +
    'Loan Amount:  ' + (si.amount  || '') + '\n' +
    'Pref. Bank:   ' + (si.bank    || 'Any') + '\n\n' +
    '── CO-APPLICANT ──\n' +
    'Name:         ' + (si.coName       || 'Not provided') + '\n' +
    'Relation:     ' + (si.coRelation   || 'Not provided') + '\n' +
    'Occupation:   ' + (si.coOccupation || 'Not provided') + '\n' +
    'Annual Income:' + (si.coIncome     || 'Not provided') + '\n\n' +
    '── DOCUMENTS UPLOADED ──\n' +
    docs + '\n\n' +
    'View in Drive: ' + folderUrl
  );

  // ── Confirmation email to student (HTML) ──
  if (si.email) {
    try {
      const docLabels = {
        aadhaar: 'Aadhaar Card', pan: 'PAN Card',
        tenth:   '10th Marksheet', twelfth: '12th Marksheet',
        admit:   'Admission Letter', income: 'Income Proof', grad: 'Graduation Marksheet', bank: 'Bank Statement',
        photo: 'Passport-size Photo', passport: 'Passport', gre: 'GRE / IELTS Score', other: 'Other Document'
      };
      const docList = (Array.isArray(data.docsUploaded) ? data.docsUploaded : [])
        .map(k => '<li style="margin:4px 0;">✅ ' + (docLabels[k] || k) + '</li>')
        .join('');

      const refId  = 'SC-' + Date.now().toString(36).toUpperCase() + '-' + (si.phone || '').slice(-4);
      const submittedAt = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });

      const htmlBody =
        '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body ' +
        'style="margin:0;padding:0;background:#f4f6f9;font-family:Arial,sans-serif;">' +

        // Wrapper
        '<table width="100%" cellpadding="0" cellspacing="0" style="background:#f4f6f9;padding:32px 0;">' +
        '<tr><td align="center">' +
        '<table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;' +
        'overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,0.08);max-width:600px;">' +

        // Header
        '<tr><td style="background:linear-gradient(135deg,#0048A8 0%,#003A8C 100%);padding:36px 40px;text-align:center;">' +
        '<h1 style="color:#ffffff;margin:0;font-size:26px;font-weight:700;letter-spacing:-0.5px;">Study LEAP</h1>' +
        '<p style="color:rgba(255,255,255,0.85);margin:6px 0 0;font-size:14px;">Education Loan Assistance</p>' +
        '</td></tr>' +

        // Success badge
        '<tr><td style="padding:36px 40px 0;text-align:center;">' +
        '<div style="display:inline-block;background:#f0fdf4;border:2px solid #22c55e;border-radius:50px;' +
        'padding:10px 24px;margin-bottom:20px;">' +
        '<span style="color:#16a34a;font-weight:700;font-size:15px;">✅ Documents Successfully Received</span>' +
        '</div>' +
        '<h2 style="margin:0 0 8px;color:#1e293b;font-size:22px;">Hi ' + esc_(si.name || 'Applicant') + '!</h2>' +
        '<p style="margin:0;color:#64748b;font-size:15px;line-height:1.6;">' +
        'We have received your loan application documents. Our team will review them and get back to you within <strong>24–48 hours</strong>.' +
        '</p>' +
        '</td></tr>' +

        // Reference ID
        '<tr><td style="padding:24px 40px 0;">' +
        '<div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:16px 20px;text-align:center;">' +
        '<p style="margin:0;color:#64748b;font-size:13px;">Your Reference ID</p>' +
        '<p style="margin:4px 0 0;color:#0048A8;font-size:20px;font-weight:700;letter-spacing:1px;">' + refId + '</p>' +
        '<p style="margin:4px 0 0;color:#94a3b8;font-size:12px;">Submitted on ' + submittedAt + '</p>' +
        '</div>' +
        '</td></tr>' +

        // Application details
        '<tr><td style="padding:24px 40px 0;">' +
        '<h3 style="margin:0 0 14px;color:#1e293b;font-size:16px;border-bottom:2px solid #e2e8f0;padding-bottom:8px;">Application Summary</h3>' +
        '<table width="100%" cellpadding="0" cellspacing="0">' +
        '<tr><td style="padding:6px 0;color:#64748b;font-size:14px;width:45%;">Course</td>' +
        '<td style="padding:6px 0;color:#1e293b;font-size:14px;font-weight:600;">' + esc_(si.course || '—') + '</td></tr>' +
        '<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">College / Country</td>' +
        '<td style="padding:6px 0;color:#1e293b;font-size:14px;font-weight:600;">' + esc_(si.college || '—') + '</td></tr>' +
        '<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">Loan Amount</td>' +
        '<td style="padding:6px 0;color:#1e293b;font-size:14px;font-weight:600;">' + esc_(si.amount || '—') + '</td></tr>' +
        '<tr><td style="padding:6px 0;color:#64748b;font-size:14px;">Phone</td>' +
        '<td style="padding:6px 0;color:#1e293b;font-size:14px;font-weight:600;">+91 ' + esc_(si.phone || '—') + '</td></tr>' +
        '</table>' +
        '</td></tr>' +

        // Documents submitted
        '<tr><td style="padding:24px 40px 0;">' +
        '<h3 style="margin:0 0 14px;color:#1e293b;font-size:16px;border-bottom:2px solid #e2e8f0;padding-bottom:8px;">Documents Submitted</h3>' +
        '<ul style="margin:0;padding:0 0 0 4px;list-style:none;color:#1e293b;font-size:14px;">' +
        docList +
        '</ul>' +
        '</td></tr>' +

        // What happens next
        '<tr><td style="padding:24px 40px 0;">' +
        '<h3 style="margin:0 0 14px;color:#1e293b;font-size:16px;border-bottom:2px solid #e2e8f0;padding-bottom:8px;">What Happens Next?</h3>' +
        '<table width="100%" cellpadding="0" cellspacing="0">' +
        '<tr><td style="padding:8px 0;vertical-align:top;width:32px;font-size:18px;">🔍</td>' +
        '<td style="padding:8px 0;color:#475569;font-size:14px;line-height:1.5;"><strong style="color:#1e293b;">Document Review</strong><br>Our team reviews your documents for completeness and eligibility.</td></tr>' +
        '<tr><td style="padding:8px 0;vertical-align:top;font-size:18px;">📞</td>' +
        '<td style="padding:8px 0;color:#475569;font-size:14px;line-height:1.5;"><strong style="color:#1e293b;">Counsellor Call</strong><br>A loan counsellor will call you within 24–48 hours to discuss the best options.</td></tr>' +
        '<tr><td style="padding:8px 0;vertical-align:top;font-size:18px;">🏦</td>' +
        '<td style="padding:8px 0;color:#475569;font-size:14px;line-height:1.5;"><strong style="color:#1e293b;">Bank Matching</strong><br>We match your profile with the best-fit lenders for fast disbursement.</td></tr>' +
        '</table>' +
        '</td></tr>' +

        // CTA button
        '<tr><td style="padding:28px 40px 0;text-align:center;">' +
        '<a href="https://wa.me/918837693510?text=Hi%2C%20my%20reference%20ID%20is%20' + refId + '" ' +
        'style="display:inline-block;background:#25d366;color:#ffffff;text-decoration:none;' +
        'padding:14px 32px;border-radius:8px;font-size:15px;font-weight:700;">💬 WhatsApp Us for Quick Help</a>' +
        '</td></tr>' +

        // Footer
        '<tr><td style="padding:32px 40px;text-align:center;border-top:1px solid #e2e8f0;margin-top:28px;">' +
        '<p style="margin:0;color:#94a3b8;font-size:13px;line-height:1.6;">' +
        'Study LEAP | Education Loan Specialists<br>' +
        '<a href="https://www.studyleap.in" style="color:#0048A8;text-decoration:none;">www.studyleap.in</a> | ' +
        '<a href="mailto:support@studyleap.in" style="color:#0048A8;text-decoration:none;">support@studyleap.in</a>' +
        '</p>' +
        '</td></tr>' +

        '</table></td></tr></table></body></html>';

      GmailApp.sendEmail(si.email,
        '✅ Documents Received – Study LEAP [Ref: ' + refId + ']',
        // Plain-text fallback
        'Dear ' + (si.name || 'Applicant') + ',\n\n' +
        'We have received your loan documents (Ref: ' + refId + ').\n\n' +
        'Docs submitted: ' + docs + '\n' +
        'Course: ' + (si.course || '') + ' | College: ' + (si.college || '') + '\n' +
        'Loan Amount: ' + (si.amount || '') + '\n\n' +
        'Our team will contact you within 24-48 hours.\n\n' +
        'WhatsApp: +91 88376 93510\n' +
        'Team Study LEAP | www.studyleap.in',
        { htmlBody: htmlBody }
      );
      Logger.log('✅ HTML confirmation email sent to student: ' + si.email + ' | Ref: ' + refId);
    } catch(e) {
      Logger.log('Student confirmation email failed: ' + e.message);
    }
  }

  Logger.log('Summary email sent for ' + si.name);
  return { ok: true, notified: true };
}

// --- TEST FUNCTIONS ---------------------------------------------------
// Builds a valid token locally so you can test without WhatsApp.
function makeTestToken_(phone) {
  const exp = String(Date.now() + 10 * 60 * 1000);
  return phone + '.' + exp + '.' + hmacHex_(getSecret_(), phone + '.' + exp);
}

// Run first: confirms UPLOAD_SECRET is set and token checking works.
function testToken() {
  const tok = makeTestToken_('9811234567');
  Logger.log('verify good token  -> ' + verifyToken_(tok));
  try { verifyToken_(tok.slice(0, -2) + 'zz'); Logger.log('FAILED: tampered token accepted'); }
  catch (e) { Logger.log('tampered token rejected OK: ' + e.message); }
  Logger.log('testToken OK');
}

// Run second: uploads a tiny PDF into Drive (also authorises Drive + Gmail access).
function testUpload() {
  const result = handleUploadFile({
    token:    makeTestToken_('9811234567'),
    docKey:   'pan',
    fileName: 'test_file.pdf',
    data:     Utilities.base64Encode('%PDF-1.4\n%Study LEAP test file\n'),
    studentInfo: { name: 'Test Student', email: 'test@example.com', course: 'Test', college: 'Test College', amount: 'Test' }
  });
  Logger.log('testUpload result: ' + JSON.stringify(result));
  Logger.log(result.ok ? 'Drive upload works!' : 'Drive upload FAILED');
}

// ─── DRIVE HELPERS ────────────────────────────────────────────────────
function getOrCreateFolder(si) {
  const root = getOrCreateRootFolder();
  const name = (si.name || 'Unknown') + ' \u2013 ' + (si.phone || '0000000000');
  const it   = root.getFoldersByName(name);
  return it.hasNext() ? it.next() : root.createFolder(name);
}

function getOrCreateRootFolder() {
  const it = DriveApp.getFoldersByName(DRIVE_FOLDER_NAME);
  return it.hasNext() ? it.next() : DriveApp.createFolder(DRIVE_FOLDER_NAME);
}

function jsonOut(obj) {
  return ContentService
    .createTextOutput(JSON.stringify({ ok: true, ...obj }))
    .setMimeType(ContentService.MimeType.JSON);
}
