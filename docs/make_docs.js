const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
  ShadingType, VerticalAlign, PageNumber, LevelFormat, ExternalHyperlink,
  PageBreak
} = require("./node_modules/docx/dist/index.cjs");
const fs = require("fs");

// ── Colour constants ──────────────────────────────────────────────
const QCI_BLUE   = "11a3d4";
const QCI_NAVY   = "1e293b";
const QCI_GREY   = "64748b";
const QCI_LIGHT  = "f1f5f9";
const QCI_WHITE  = "FFFFFF";
const QCI_AMBER  = "d97706";
const QCI_RED    = "dc2626";
const QCI_GREEN  = "166534";

// ── A4 page dimensions (DXA) ──────────────────────────────────────
const A4_W = 11906;
const A4_H = 16838;
const MARGIN = 1418; // ~2.5cm
const CONTENT_W = A4_W - MARGIN * 2; // 9070

// ── Shared border helper ──────────────────────────────────────────
const border1 = (color = "CCCCCC") => ({ style: BorderStyle.SINGLE, size: 4, color });
const borders  = (color = "CCCCCC") => ({ top: border1(color), bottom: border1(color), left: border1(color), right: border1(color) });
const noBorder = () => ({ style: BorderStyle.NONE, size: 0, color: "FFFFFF" });
const noBorders = () => ({ top: noBorder(), bottom: noBorder(), left: noBorder(), right: noBorder() });

// ── Page properties shared across all docs ────────────────────────
const pageProps = {
  size: { width: A4_W, height: A4_H },
  margin: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN, header: 500, footer: 500 }
};

// ── Standard header ───────────────────────────────────────────────
function makeHeader() {
  return new Header({
    children: [new Paragraph({
      alignment: AlignmentType.RIGHT,
      border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: QCI_BLUE, space: 4 } },
      children: [
        new TextRun({ text: "QCI Notify", bold: true, color: QCI_BLUE, size: 18, font: "Calibri" }),
        new TextRun({ text: "  |  Quality Council of India", color: QCI_GREY, size: 18, font: "Calibri" }),
      ]
    })]
  });
}

// ── Standard footer ───────────────────────────────────────────────
function makeFooter() {
  return new Footer({
    children: [new Paragraph({
      alignment: AlignmentType.CENTER,
      border: { top: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 4 } },
      children: [
        new TextRun({ text: "Confidential — QCI Internal Document  |  Page ", color: QCI_GREY, size: 16, font: "Calibri" }),
        new TextRun({ children: [PageNumber.CURRENT], color: QCI_GREY, size: 16, font: "Calibri" }),
        new TextRun({ text: " of ", color: QCI_GREY, size: 16, font: "Calibri" }),
        new TextRun({ children: [PageNumber.TOTAL_PAGES], color: QCI_GREY, size: 16, font: "Calibri" }),
      ]
    })]
  });
}

// ── Logo block ────────────────────────────────────────────────────
function logoBlock(subtitle) {
  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: [CONTENT_W],
    rows: [
      new TableRow({ children: [
        new TableCell({
          width: { size: CONTENT_W, type: WidthType.DXA },
          borders: { top: border1(QCI_BLUE), bottom: border1(QCI_BLUE), left: { style: BorderStyle.THICK, size: 18, color: QCI_BLUE }, right: noBorder() },
          shading: { fill: "EBF8FD", type: ShadingType.CLEAR },
          margins: { top: 180, bottom: 180, left: 280, right: 200 },
          children: [
            new Paragraph({ children: [
              new TextRun({ text: "QCI", bold: true, color: QCI_BLUE, size: 52, font: "Calibri" }),
              new TextRun({ text: " Notify", bold: true, color: QCI_NAVY, size: 52, font: "Calibri" }),
            ]}),
            new Paragraph({ children: [
              new TextRun({ text: "Quality Council of India — Notification Engine", color: QCI_GREY, size: 20, font: "Calibri", italics: true }),
            ]}),
            new Paragraph({ spacing: { before: 60 }, children: [
              new TextRun({ text: subtitle, color: QCI_NAVY, size: 24, font: "Calibri", bold: true }),
            ]}),
          ]
        })
      ]}),
    ]
  });
}

// ── Screenshot placeholder (removed — not needed for shareable version) ──
function screenshotPlaceholder(_caption) { return []; }

// ── Heading helpers ───────────────────────────────────────────────
function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 360, after: 120 },
    border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: QCI_BLUE, space: 4 } },
    children: [new TextRun({ text, bold: true, color: QCI_BLUE, size: 32, font: "Calibri" })]
  });
}
function h2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 240, after: 80 },
    children: [new TextRun({ text, bold: true, color: QCI_NAVY, size: 26, font: "Calibri" })]
  });
}
function h3(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 160, after: 60 },
    children: [new TextRun({ text, bold: true, color: QCI_GREY, size: 22, font: "Calibri" })]
  });
}
function body(text, opts = {}) {
  return new Paragraph({
    spacing: { before: 60, after: 100 },
    children: [new TextRun({ text, size: 22, font: "Calibri", ...opts })]
  });
}
function bullet(text, bold_prefix = null) {
  const children = [];
  if (bold_prefix) {
    children.push(new TextRun({ text: bold_prefix + " ", bold: true, size: 22, font: "Calibri" }));
    children.push(new TextRun({ text, size: 22, font: "Calibri" }));
  } else {
    children.push(new TextRun({ text, size: 22, font: "Calibri" }));
  }
  return new Paragraph({
    numbering: { reference: "bullets", level: 0 },
    spacing: { before: 40, after: 60 },
    children
  });
}
function numbered(text, bold_prefix = null) {
  const children = [];
  if (bold_prefix) {
    children.push(new TextRun({ text: bold_prefix + " ", bold: true, size: 22, font: "Calibri" }));
    children.push(new TextRun({ text, size: 22, font: "Calibri" }));
  } else {
    children.push(new TextRun({ text, size: 22, font: "Calibri" }));
  }
  return new Paragraph({
    numbering: { reference: "numbers", level: 0 },
    spacing: { before: 40, after: 60 },
    children
  });
}
function code(text) {
  return new Paragraph({
    spacing: { before: 80, after: 80 },
    shading: { fill: "F8FAFC", type: ShadingType.CLEAR },
    border: { left: { style: BorderStyle.THICK, size: 12, color: QCI_BLUE, space: 8 } },
    children: [new TextRun({ text, font: "Courier New", size: 18, color: "334155" })]
  });
}
function tip(text) {
  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: [CONTENT_W],
    rows: [new TableRow({ children: [new TableCell({
      width: { size: CONTENT_W, type: WidthType.DXA },
      borders: { top: noBorder(), bottom: noBorder(), right: noBorder(), left: { style: BorderStyle.THICK, size: 18, color: QCI_BLUE, space: 0 } },
      shading: { fill: "EBF8FD", type: ShadingType.CLEAR },
      margins: { top: 100, bottom: 100, left: 200, right: 200 },
      children: [new Paragraph({ children: [
        new TextRun({ text: "💡 Tip: ", bold: true, color: QCI_BLUE, size: 20, font: "Calibri" }),
        new TextRun({ text, size: 20, font: "Calibri", color: "334155" }),
      ]})]
    })]})],
  });
}
function warning(text) {
  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: [CONTENT_W],
    rows: [new TableRow({ children: [new TableCell({
      width: { size: CONTENT_W, type: WidthType.DXA },
      borders: { top: noBorder(), bottom: noBorder(), right: noBorder(), left: { style: BorderStyle.THICK, size: 18, color: QCI_AMBER, space: 0 } },
      shading: { fill: "FFFBEB", type: ShadingType.CLEAR },
      margins: { top: 100, bottom: 100, left: 200, right: 200 },
      children: [new Paragraph({ children: [
        new TextRun({ text: "⚠ Important: ", bold: true, color: QCI_AMBER, size: 20, font: "Calibri" }),
        new TextRun({ text, size: 20, font: "Calibri", color: "334155" }),
      ]})]
    })]})],
  });
}
function spacer(before = 120) {
  return new Paragraph({ spacing: { before }, children: [] });
}
function pageBreak() {
  return new Paragraph({ children: [new PageBreak()] });
}

// ── Table builder ─────────────────────────────────────────────────
function dataTable(headers, rows) {
  const colCount = headers.length;
  const colW = Math.floor(CONTENT_W / colCount);
  const colWidths = Array(colCount).fill(colW);
  // adjust last col for rounding
  colWidths[colCount - 1] = CONTENT_W - colW * (colCount - 1);

  const headerRow = new TableRow({
    tableHeader: true,
    children: headers.map((h, i) => new TableCell({
      width: { size: colWidths[i], type: WidthType.DXA },
      borders: borders(QCI_BLUE),
      shading: { fill: QCI_BLUE, type: ShadingType.CLEAR },
      margins: { top: 80, bottom: 80, left: 120, right: 120 },
      children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, color: QCI_WHITE, size: 18, font: "Calibri" })] })]
    }))
  });

  const dataRows = rows.map((row, ri) => new TableRow({
    children: row.map((cell, i) => new TableCell({
      width: { size: colWidths[i], type: WidthType.DXA },
      borders: borders(),
      shading: { fill: ri % 2 === 0 ? "F8FAFC" : QCI_WHITE, type: ShadingType.CLEAR },
      margins: { top: 60, bottom: 60, left: 120, right: 120 },
      children: [new Paragraph({ children: [new TextRun({ text: String(cell), size: 18, font: "Calibri" })] })]
    }))
  }));

  return new Table({
    width: { size: CONTENT_W, type: WidthType.DXA },
    columnWidths: colWidths,
    rows: [headerRow, ...dataRows],
  });
}

// ── Numbering config ──────────────────────────────────────────────
const numbering = {
  config: [
    { reference: "bullets", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    { reference: "numbers", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 720, hanging: 360 } } } }] },
    { reference: "alpha",   levels: [{ level: 0, format: LevelFormat.LOWER_LETTER, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 1080, hanging: 360 } } } }] },
  ]
};
const styles = {
  default: { document: { run: { font: "Calibri", size: 22 } } },
  paragraphStyles: [
    { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
      run: { size: 32, bold: true, font: "Calibri", color: QCI_BLUE },
      paragraph: { spacing: { before: 360, after: 120 }, outlineLevel: 0 } },
    { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
      run: { size: 26, bold: true, font: "Calibri", color: QCI_NAVY },
      paragraph: { spacing: { before: 240, after: 80 }, outlineLevel: 1 } },
    { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
      run: { size: 22, bold: true, font: "Calibri", color: QCI_GREY },
      paragraph: { spacing: { before: 160, after: 60 }, outlineLevel: 2 } },
  ]
};

// ════════════════════════════════════════════════════════════════════
// DOCUMENT 1: SYSTEM INFORMATION
// ════════════════════════════════════════════════════════════════════
function buildSystemDoc() {
  const children = [
    logoBlock("System Technical Reference"),
    spacer(200),
    body("Version: 1.0   |   Deployment: https://web-production-c0ec0.up.railway.app   |   Last Updated: 30 March 2026", { color: QCI_GREY }),
    spacer(100),

    h1("1. System Overview"),
    h2("Purpose"),
    body("QCI Notification Engine is a web-based CRM for managing case workflows across structured multi-stage processes (programmes). It tracks turnaround times (TAT) for each case stage and sends automated email notifications — reminders before deadlines, overdue alerts, escalation emails, and weekly digest summaries — to ensure timely action by responsible parties."),
    body("Primary use cases include accreditation workflows, hospital quality certifications, and any process where a case must progress through predefined stages with time-bound accountability."),
    spacer(),

    h2("Architecture"),
    ...screenshotPlaceholder("Screenshot: System Architecture Diagram"),
    body("The system follows a standard three-tier web application architecture:"),
    bullet("Browser communicates over HTTPS to Gunicorn (WSGI server)"),
    bullet("Gunicorn serves the Flask 3 application"),
    bullet("Flask handles routing, business logic, sessions, and REST API endpoints"),
    bullet("PostgreSQL stores all persistent data via psycopg2 with connection pooling"),
    bullet("APScheduler runs inside the Gunicorn worker for daily and weekly scheduled jobs"),
    spacer(),

    h2("Tech Stack"),
    dataTable(
      ["Component", "Technology", "Version / Notes"],
      [
        ["Web Framework",    "Flask",              "3.x"],
        ["Database",         "PostgreSQL",         "Managed on Railway"],
        ["DB Driver",        "psycopg2",           "Connection pool via SimpleConnectionPool"],
        ["WSGI Server",      "Gunicorn",           "1 worker (APScheduler constraint)"],
        ["Background Jobs",  "APScheduler",        "BackgroundScheduler, Asia/Kolkata timezone"],
        ["Email Dispatch",   "smtplib (SMTP)",     "Configurable per board, pooled connections"],
        ["Encryption",       "cryptography/Fernet","SMTP passwords encrypted at rest"],
        ["2FA",              "pyotp (TOTP)",       "Optional per user"],
        ["Deployment",       "Render",             "Web service + PostgreSQL add-on"],
        ["Frontend",         "Jinja2 + HTML/CSS",  "No frontend framework"],
      ]
    ),
    spacer(),

    pageBreak(),
    h1("2. Database Schema"),
    body("All tables reside in the default PostgreSQL schema. The application uses psycopg2 with a SimpleConnectionPool (min=1, max=10)."),
    ...screenshotPlaceholder("Screenshot: Database Schema ERD"),
    spacer(),

    h2("2.1 users"),
    dataTable(["Column","Type","Description"],[
      ["id","SERIAL PK","Auto-increment user ID"],
      ["username","TEXT UNIQUE","Login username"],
      ["password_hash","TEXT","Bcrypt-hashed password"],
      ["role","TEXT","super_admin / board_admin / board_ceo / program_head / program_officer"],
      ["board_id","INTEGER FK","Board the user belongs to (NULL for super_admin)"],
      ["email","TEXT","Email for notifications"],
      ["full_name","TEXT","Display name"],
      ["totp_secret","TEXT","TOTP secret for 2FA (stored server-side only)"],
      ["force_password_reset","INTEGER","1 = redirect to reset on next login"],
      ["last_login","TEXT","Timestamp of last successful login"],
    ]),
    spacer(),

    h2("2.2 boards"),
    dataTable(["Column","Type","Description"],[
      ["id","SERIAL PK","Board ID"],
      ["board_name","TEXT UNIQUE","Display name for the board"],
    ]),
    spacer(),

    h2("2.3 programmes"),
    dataTable(["Column","Type","Description"],[
      ["id","SERIAL PK","Programme ID"],
      ["programme_name","TEXT UNIQUE","Programme name"],
      ["board_id","INTEGER FK","Owning board"],
      ["tat_days","INTEGER","Default TAT at programme level"],
      ["reminder1_days","INTEGER","Default R1 threshold"],
      ["reminder2_days","INTEGER","Default R2 threshold"],
      ["overdue_days","INTEGER","Default overdue interval"],
      ["notification_emails","TEXT","Comma-separated notification recipients"],
    ]),
    spacer(),

    h2("2.4 programme_config (Stages)"),
    dataTable(["Column","Type","Description"],[
      ["id","SERIAL PK","Stage record ID"],
      ["programme_name","TEXT","Parent programme"],
      ["stage_name","TEXT","Stage display name"],
      ["stage_order","INTEGER","Sequence index"],
      ["tat_days","INTEGER","Target turnaround days for this stage"],
      ["reminder1_day","INTEGER","Days before TAT to send R1"],
      ["reminder2_day","INTEGER","Days before TAT to send R2"],
      ["owner_type","TEXT","Who owns the stage action"],
      ["overdue_interval_days","INTEGER","Frequency of Followup notifications"],
      ["is_milestone","INTEGER","1 = milestone stage (no TAT calculation)"],
      ["is_optional","INTEGER","1 = stage can be skipped"],
      ["sender_email","TEXT","Override From address for this stage"],
      ["smtp_host/port","TEXT/INT","Stage-specific SMTP config"],
    ]),
    spacer(),

    h2("2.5 case_tracking"),
    dataTable(["Column","Type","Description"],[
      ["id","SERIAL PK","Internal case ID"],
      ["application_id","TEXT UNIQUE","External application identifier"],
      ["organisation_name","TEXT","Organisation name"],
      ["programme_name","TEXT","Programme this case is in"],
      ["current_stage","TEXT","Stage the case is currently at"],
      ["stage_start_date","TEXT","Date current stage began (YYYY-MM-DD)"],
      ["action_owner_name/email","TEXT","Responsible person"],
      ["program_officer_email","TEXT","Assigned program officer"],
      ["cc_emails","TEXT","Comma-separated CC addresses"],
      ["status","TEXT","Active / On Hold / Closed / Withdrawn / Suspended"],
      ["r1_sent / r2_sent","INTEGER","Whether R1/R2 reminders sent this stage"],
      ["overdue_sent","INTEGER","Whether initial overdue notice sent"],
      ["overdue_count","INTEGER","Number of followup emails sent"],
      ["hold_days","INTEGER","Total days on hold (subtracted from TAT)"],
      ["board_id","INTEGER FK","Board this case belongs to"],
    ]),
    spacer(),

    h2("2.6 Additional Tables"),
    dataTable(["Table","Purpose"],[
      ["stage_history","Immutable log of all stage transitions"],
      ["email_queue","Outbound email jobs (pending/sent/failed)"],
      ["email_templates","Customisable templates per notification type"],
      ["stage_email_override","Per-stage template overrides"],
      ["app_settings","Key-value config store (scheduler, digest, webhook)"],
      ["audit_log","Tamper-evident event log with SHA-256 hash chain"],
      ["holidays","Holiday calendar (dates excluded from TAT calculation)"],
      ["user_programme_map","User-to-programme assignments"],
      ["saved_filters","Saved dashboard filter presets per user"],
      ["api_keys","Machine-to-machine API key registry"],
      ["scheduler_locks","Distributed lock for daily scheduler (prevents duplicates)"],
    ]),
    spacer(),

    pageBreak(),
    h1("3. Configuration Reference"),
    body("All settings are stored in the app_settings table. System-wide settings have board_id = NULL; board-specific settings carry the relevant board_id."),
    spacer(),

    h2("System-Wide Settings"),
    dataTable(["Key","Type","Default","Description"],[
      ["scheduler_hour","integer 0–23","8","Hour (IST) for daily notification check"],
      ["scheduler_minute","integer 0–59","0","Minute for daily notification check"],
      ["digest_enabled","'1' or '0'","'1'","Whether weekly digest emails are sent"],
      ["ph_escalation_days","integer","5","Days overdue before escalating to Program Head"],
      ["webhook_url","URL string","empty","POST to this URL on case advance / email send"],
    ]),
    spacer(),

    h2("Board-Level Settings"),
    dataTable(["Key","Description"],[
      ["smtp_host","SMTP server hostname for this board"],
      ["smtp_port","SMTP port (587 = STARTTLS, 465 = SSL)"],
      ["smtp_user","SMTP authentication username"],
      ["smtp_password_enc","Fernet-encrypted SMTP password"],
      ["default_sender_email","Default From address for board emails"],
    ]),
    spacer(),

    pageBreak(),
    h1("4. Email System"),
    h2("Notification Types"),
    dataTable(["Type","Trigger","Recipients"],[
      ["R1 — First Reminder","tat_days - days_elapsed == reminder1_day","Action owner + Program officer"],
      ["R2 — Second Reminder","tat_days - days_elapsed == reminder2_day","Action owner + Program officer"],
      ["Overdue","days_elapsed > tat_days AND overdue_sent = FALSE","Action owner + Program officer"],
      ["Followup","Overdue AND days since last followup >= overdue_interval_days","Action owner + Program officer + Program Head (if escalation threshold met)"],
      ["Weekly Digest","Every Monday 08:00 IST (if digest_enabled = '1')","Board CEOs + Program Heads"],
    ]),
    spacer(),

    h2("Template Placeholders"),
    dataTable(["Placeholder","Resolved Value"],[
      ["{{Stage_Name}}","Current stage name"],
      ["{{Organisation_Name}}","Organisation name from the case"],
      ["{{Programme_Name}}","Programme name"],
      ["{{Action_Owner_Name}}","Name of the action owner"],
      ["{{Action_Owner_Email}}","Email of the action owner"],
      ["{{PO_Name}}","Program officer name (looked up from email)"],
      ["{{Days_Remaining}}","Days until TAT breach (R1/R2)"],
      ["{{Days_Overdue}}","Days past TAT (Overdue/Followup)"],
      ["{{Followup_Count}}","Number of followup emails sent so far"],
      ["{{Stage_Start_Date}}","Date current stage began (DD/MM/YYYY)"],
    ]),
    spacer(),

    h2("Email Queue System"),
    ...screenshotPlaceholder("Screenshot: Email Queue Dashboard"),
    body("Emails are never sent synchronously during an HTTP request. The notification check writes jobs to email_queue with status='pending'. A dispatch step reads pending emails, attempts SMTP delivery, and updates status to 'sent' or 'failed'. SMTP connections are pooled by sender credentials — one connection per group of emails, not one per email."),
    spacer(),

    h2("SMTP Configuration Priority"),
    body("Highest priority wins:"),
    numbered("Stage-level SMTP config"),
    numbered("Board-level SMTP config"),
    numbered("System-level fallback SMTP (environment variables)"),
    spacer(),

    pageBreak(),
    h1("5. Scheduler"),
    h2("Daily Notification Check"),
    body("Runs once per day at the time configured by scheduler_hour / scheduler_minute (IST). Steps:"),
    numbered("Query all cases with status = 'Active'"),
    numbered("For each case: compute days_elapsed = today - stage_start_date (excluding weekends and holidays)"),
    numbered("Evaluate R1, R2, Overdue, Followup eligibility and enqueue matching email jobs"),
    numbered("Dispatch the email queue (SMTP send loop with connection pooling)"),
    numbered("Write all actions to the audit log"),
    spacer(),

    h2("Scheduler Settings Panel"),
    ...screenshotPlaceholder("Screenshot: Scheduler Settings Panel"),

    h2("Weekly Digest"),
    body("Runs every Monday at 08:00 IST (fixed). Enabled/disabled via digest_enabled setting. Digest includes: total active cases per programme, overdue cases, cases approaching TAT, cases on hold. Recipients: board_ceo and program_head users for the relevant board."),
    spacer(),

    h2("APScheduler vs External Cron"),
    body("On Railway (single-worker deployment): APScheduler runs inside Gunicorn. For multi-instance or serverless deployments, set DISABLE_APSCHEDULER=true and use an external cron to call GET /run-check on schedule."),
    spacer(),

    pageBreak(),
    h1("6. Security"),
    h2("Role-Based Access Control (RBAC)"),
    dataTable(["Role","Access Level"],[
      ["super_admin","Full access: all boards, system settings, scheduler, API keys, audit log"],
      ["board_admin","Full access to their board: programmes, stages, users, email, SMTP"],
      ["board_ceo","Read-only dashboard for their board; receives weekly digest"],
      ["program_head","View cases in their programme; receives escalation emails"],
      ["program_officer","Create/edit/advance cases in their board's programmes"],
    ]),
    spacer(),

    h2("Authentication"),
    bullet("Sessions: Flask signed cookies with SECRET_KEY, 8-hour inactivity timeout"),
    bullet("Passwords: Bcrypt hashed, never stored plaintext"),
    bullet("2FA: TOTP via pyotp — QR code shown once, 6-digit codes thereafter"),
    bullet("Force Reset: board_admin can flag any user to reset password on next login"),
    spacer(),

    h2("API Key Authentication"),
    body("Raw key shown only once at creation. Server stores SHA-256 hash only. Every API request must include X-API-Key header. Keys are board-scoped — cannot access other boards' data."),
    spacer(),

    h2("Fernet Encryption"),
    body("SMTP passwords are encrypted at rest using Fernet (cryptography library). Key = FERNET_KEY environment variable (32-byte URL-safe base64). Loss of this key requires re-entering all SMTP passwords."),
    spacer(),

    h2("Audit Log Hash-Chaining"),
    ...screenshotPlaceholder("Screenshot: Audit Log with Hash Chain"),
    body("Each audit log row contains: prev_hash (hash of the previous row) and row_hash (SHA-256 of event_type + actor + target + detail + timestamp + prev_hash). Tampering with any historical row breaks the chain from that point forward. The audit log page displays a chain-valid indicator."),
    spacer(),

    pageBreak(),
    h1("7. Deployment"),
    h2("Required Environment Variables"),
    dataTable(["Variable","Description","Example"],[
      ["DATABASE_URL","PostgreSQL connection string","postgresql://user:pass@host:5432/db"],
      ["SECRET_KEY","Flask session signing key (64-char hex)","3c6cd977f7ce..."],
      ["FERNET_KEY","Fernet key for SMTP password encryption","bb4pSsPXTV...="],
      ["DISABLE_APSCHEDULER","Set 'true' to disable in-process scheduler","false (default)"],
      ["ADMIN_EMAIL","Super admin email for first-run setup","admin@example.com"],
    ]),
    spacer(),

    h2("Railway Setup Steps"),
    numbered("Create Render Web Service from GitHub repository"),
    numbered("Runtime: Python 3, Start command: gunicorn app:app --workers 1 --bind 0.0.0.0:$PORT"),
    numbered("Add Render PostgreSQL add-on (DATABASE_URL auto-injected)"),
    numbered("Set SECRET_KEY, FERNET_KEY, and other env vars in Render dashboard"),
    numbered("First deploy: app auto-creates tables and seeds super_admin account"),
    numbered("Use --workers 1 only, to prevent duplicate APScheduler job runs"),
    spacer(),

    h2("Health Check"),
    code("GET /healthz — No auth required"),
    code('Response: {"status":"ok","user_count":42,"admin_exists":true,"db_path":"postgresql://..."}'),
    spacer(),

    pageBreak(),
    h1("8. Audit Trail"),
    body("The audit log records every significant system event with a tamper-evident SHA-256 hash chain. Events logged include:"),
    dataTable(["Event Type","Description"],[
      ["login / login_failed","Successful and failed login attempts"],
      ["logout","User session ended"],
      ["password_reset","Password change (forced or voluntary)"],
      ["case_created","New case logged in the system"],
      ["case_advanced","Case moved to next stage"],
      ["case_status_changed","Status updated (Active/On Hold/Closed/etc.)"],
      ["case_edited","Case fields edited"],
      ["case_deleted","Case permanently deleted"],
      ["bulk_upload","Bulk upload completed (with row count)"],
      ["email_sent / email_failed","Email dispatch success or failure"],
      ["settings_changed","App settings modified"],
      ["user_created / user_edited / user_deleted","User account lifecycle events"],
      ["api_key_created / api_key_revoked","API key lifecycle events"],
      ["scheduler_run","Scheduled notification check executed"],
      ["stage_skipped","Optional stage skipped during advance"],
      ["webhook_sent","Outbound webhook dispatched"],
    ]),
    spacer(),

    pageBreak(),
    h1("9. Performance Notes"),
    h2("Connection Pooling"),
    body("psycopg2 SimpleConnectionPool with min=1, max=10 connections. Connections checked out at request start, returned after response. Rollback-before-return prevents InFailedSqlTransaction errors on reuse."),
    h2("Email Dispatch (SMTP and SendGrid API)"),
    body("The system supports two outbound email providers selectable per programme: direct SMTP (Gmail, Outlook, any SMTP relay) and SendGrid HTTP API. Set provider in Settings → Outbound Email Settings. During daily check, SMTP emails are grouped by credentials — one connection per group. SendGrid emails are dispatched individually via HTTPS POST to api.sendgrid.com/v3/mail/send. No additional Python packages are required for SendGrid (uses urllib.request)."),
    spacer(),
    h2("AWS Migration Checklist"),
    body("Items to address when migrating from Railway to AWS:"),
    bullet("Provision RDS PostgreSQL instance; update DATABASE_URL environment variable"),
    bullet("Confirm outbound TCP on ports 587/465 from EC2/ECS security group — or keep SendGrid as the email provider to avoid SMTP port issues entirely"),
    bullet("Re-enter or re-encrypt SMTP/SendGrid credentials if FERNET_KEY changes"),
    bullet("Move init_db() call out of module import time (currently blocks gunicorn worker boot) — extract to a one-time migration script or Flask CLI command"),
    bullet("With multi-worker deployment (workers > 1), disable in-process APScheduler (DISABLE_APSCHEDULER=true) and run the scheduler as a separate process or AWS EventBridge rule hitting /run-check"),
    bullet("Review SECRET_KEY rotation — existing sessions will be invalidated"),
    bullet("Confirm /healthz endpoint is reachable by the ALB/ELB health check target"),
    spacer(),
    h2("Pagination"),
    body("All list views paginated server-side (default 50 rows). /api/v1/cases supports limit/offset. Large Excel exports use openpyxl streaming to avoid loading all rows into memory."),
    h2("Working Days Calculation"),
    body("TAT calculations exclude weekends and Indian public holidays (stored in the holidays table). Hold days are also subtracted from elapsed time for On Hold cases."),
    spacer(300),
  ];

  return new Document({ numbering, styles, sections: [{ properties: { page: pageProps }, headers: { default: makeHeader() }, footers: { default: makeFooter() }, children }] });
}

// ════════════════════════════════════════════════════════════════════
// DOCUMENT 2: API DOCUMENTATION
// ════════════════════════════════════════════════════════════════════
function buildApiDoc() {
  const children = [
    logoBlock("API Integration Guide"),
    spacer(200),
    body("Version: 1.0   |   Base URL: https://web-production-c0ec0.up.railway.app   |   Last Updated: 30 March 2026", { color: QCI_GREY }),
    body("Intended for developers integrating an external system with QCI Notification Engine.", { italics: true }),
    spacer(100),

    h1("1. Overview"),
    body("The QCI Notification Engine exposes a REST API for programmatic access to case management operations. The API supports:"),
    bullet("Advancing cases through workflow stages from an external system"),
    bullet("Reading case status for a specific application"),
    bullet("Listing cases with optional filtering"),
    bullet("Health checking the service uptime and database connectivity"),
    spacer(),
    body("All API endpoints (except /healthz) require authentication via an API key in the request header. All communication is over HTTPS. Request and response bodies use JSON."),
    code("Base URL: https://web-production-c0ec0.up.railway.app"),
    spacer(),

    h1("2. Authentication"),
    h2("Creating an API Key"),
    ...screenshotPlaceholder("Screenshot: API Keys Management Page"),
    body("API keys are managed through the web interface by users with board_admin or super_admin roles:"),
    numbered("Log in to https://web-production-c0ec0.up.railway.app"),
    numbered("Navigate to Settings → API Keys (or /api-keys)"),
    numbered("Click Generate New Key"),
    numbered("Enter a descriptive label (e.g., hospital-mis-integration)"),
    numbered("The raw key is displayed ONCE. Copy it immediately and store securely."),
    numbered("The system stores only a hash — the key cannot be shown again."),
    spacer(),
    ...screenshotPlaceholder("Screenshot: Creating a New API Key"),
    spacer(),

    h2("Using the API Key"),
    body("Include the raw key in every request using the X-API-Key HTTP header:"),
    code("X-API-Key: qci_live_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
    spacer(),
    warning("There is no Bearer token or OAuth flow. Every request to a protected endpoint must include this header."),
    spacer(),

    h2("Board Scoping"),
    ...screenshotPlaceholder("Screenshot: API Key with Board Scope"),
    body("Each API key is scoped to exactly one board:"),
    bullet("POST /api/v1/cases/advance — creates/advances cases within the key's board only"),
    bullet("GET /api/v1/cases — returns cases from the key's board only"),
    bullet("Accessing a case from a different board returns 403 Forbidden"),
    spacer(),

    h1("3. Rate Limits and Notes"),
    dataTable(["Item","Detail"],[
      ["Rate limits","None enforced at the API layer currently"],
      ["Cold start","Render free tier may take 20–30 seconds on first request after idle. Build retry logic."],
      ["Timestamps","All timestamps returned in ISO 8601 format (UTC)"],
      ["Date format","Accepted: YYYY-MM-DD (recommended), DD/MM/YYYY, MM/DD/YYYY, DD-MM-YYYY"],
      ["Updates","No PATCH support. To update a case, advance it via POST /api/v1/cases/advance"],
      ["Case sensitivity","All string fields (stage_name, programme_name) are case-sensitive"],
    ]),
    spacer(),

    pageBreak(),
    h1("4. API Endpoints"),
    h2("4.1 POST /api/v1/cases/advance"),
    body("Advance a case to a specified stage, or create it if it does not yet exist. This is the primary write endpoint."),
    spacer(),

    h3("Request"),
    dataTable(["Header","Required","Description"],[
      ["X-API-Key","Yes","Your board's API key"],
      ["Content-Type","Yes","application/json"],
    ]),
    spacer(),

    h3("Request Body"),
    dataTable(["Field","Type","Required","Description"],[
      ["application_id","string","Yes","Unique identifier (your system's ID)"],
      ["stage_name","string","Yes","Exact stage name (must exist in the programme)"],
      ["programme_name","string","Yes","Exact programme name (must exist in your board)"],
      ["organisation_name","string","Yes","Name of the organisation"],
      ["stage_start_date","string","Yes","Date stage began (YYYY-MM-DD recommended)"],
      ["action_owner_name","string","Yes","Full name of person responsible for this stage"],
      ["action_owner_email","string","Yes","Email of action owner (receives R1/R2/Overdue)"],
      ["program_officer_email","string","Yes","Email of program officer overseeing the case"],
      ["changed_by","string","No","Your system's identifier for this actor (audit log)"],
      ["cc_emails","string","No","Comma-separated CC email addresses"],
    ]),
    spacer(),

    h3("Example Request Body"),
    code('{"application_id": "NABH-2025-00412",'),
    code(' "stage_name": "Document Review",'),
    code(' "programme_name": "NABH Hospital Accreditation",'),
    code(' "organisation_name": "City General Hospital",'),
    code(' "stage_start_date": "2026-03-20",'),
    code(' "action_owner_name": "Dr. Priya Sharma",'),
    code(' "action_owner_email": "priya.sharma@cityhospital.in",'),
    code(' "program_officer_email": "officer@qci.org.in",'),
    code(' "changed_by": "mis-system-prod"}'),
    spacer(),

    h3("Success Response (200 OK)"),
    code('{"ok": true, "action": "advanced", "application_id": "NABH-2025-00412"}'),
    body("The action field returns 'created' for new cases, 'advanced' for existing."),
    spacer(),

    h3("Error Responses"),
    dataTable(["HTTP Status","Example Response"],[
      ["400 Bad Request",'{"ok": false, "error": "Missing required field: stage_name"}'],
      ["401 Unauthorized",'{"ok": false, "error": "Invalid or missing API key"}'],
      ["403 Forbidden",'{"ok": false, "error": "Programme not authorised for this API key"}'],
      ["404 Not Found",'{"ok": false, "error": "Stage not found in programme"}'],
    ]),
    spacer(),

    h3("curl Example"),
    code("curl -X POST https://web-production-c0ec0.up.railway.app/api/v1/cases/advance \\"),
    code('  -H "X-API-Key: qci_live_xxxxxxxx" \\'),
    code('  -H "Content-Type: application/json" \\'),
    code("  -d '{\"application_id\":\"NABH-2025-00412\",\"stage_name\":\"Document Review\",...}'"),
    spacer(),

    h3("Python Example"),
    code("import requests"),
    code('response = requests.post('),
    code('    "https://web-production-c0ec0.up.railway.app/api/v1/cases/advance",'),
    code('    headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},'),
    code("    json={\"application_id\": \"NABH-2025-00412\", ...},"),
    code("    timeout=30)"),
    code("result = response.json()  # {'ok': True, 'action': 'advanced', ...}"),
    spacer(),

    pageBreak(),
    h2("4.2 GET /api/v1/cases/:app_id"),
    body("Retrieve full details of a specific case by its application ID."),
    spacer(),
    h3("Request"),
    code("GET /api/v1/cases/NABH-2025-00412"),
    code("X-API-Key: qci_live_xxxxxxxx"),
    spacer(),
    h3("Success Response"),
    code('{"ok": true, "case": {'),
    code('  "application_id": "NABH-2025-00412",'),
    code('  "organisation_name": "City General Hospital",'),
    code('  "stage_name": "Document Review",'),
    code('  "status": "Active",'),
    code('  "days_elapsed": 6,'),
    code('  "tat_days": 30,'),
    code('  "days_remaining": 24,'),
    code('  "is_overdue": false,'),
    code('  "r1_sent": false, "r2_sent": false, "overdue_sent": false}}'),
    spacer(),

    h2("4.3 GET /api/v1/cases"),
    body("List cases with optional filtering. Returns summary representation (use GET /api/v1/cases/:id for full detail)."),
    spacer(),
    h3("Query Parameters"),
    dataTable(["Parameter","Type","Description"],[
      ["programme","string","Filter by programme name (exact match)"],
      ["status","string","Active / On Hold / Closed / Withdrawn / Suspended"],
      ["limit","integer","Max results (default 100, max 1000)"],
      ["offset","integer","Skip N results for pagination (default 0)"],
    ]),
    spacer(),
    h3("curl Examples"),
    code("# Filter by programme and status"),
    code("curl 'https://web-production-c0ec0.up.railway.app/api/v1/cases?programme=NABH...&status=Active' \\"),
    code('  -H "X-API-Key: qci_live_xxxxxxxx"'),
    code(""),
    code("# Paginate (second page of 50)"),
    code("curl 'https://web-production-c0ec0.up.railway.app/api/v1/cases?limit=50&offset=50' \\"),
    code('  -H "X-API-Key: qci_live_xxxxxxxx"'),
    spacer(),

    h2("4.4 GET /healthz"),
    body("Public health check. No authentication required. Used by Railway for uptime monitoring."),
    code("curl https://web-production-c0ec0.up.railway.app/healthz"),
    code('# {"status": "ok", "user_count": 42, "admin_exists": true}'),
    spacer(),

    h2("4.5 GET /api/stages (Internal)"),
    body("Returns stage list for a programme. Requires browser session login (not API key). Intended for UI AJAX calls. For integration purposes, configure stage names in your external system manually — they are defined by board admins and rarely change."),
    code("GET /api/stages?programme=NABH%20Hospital%20Accreditation"),
    spacer(),

    pageBreak(),
    h1("5. Webhook Integration"),
    h2("Configuration"),
    ...screenshotPlaceholder("Screenshot: Webhook Configuration"),
    body("To receive real-time event notifications in your system:"),
    numbered("Log in as board_admin or super_admin"),
    numbered("Navigate to Settings → System Settings"),
    numbered("Set the Webhook URL field to your HTTPS endpoint"),
    numbered("Save settings"),
    spacer(),
    body("The system will POST to this URL on: case advances (UI or API), successful email dispatches, and scheduled check completions."),
    spacer(),

    h2("Webhook Payload — Case Advanced"),
    code('{"event": "case_advanced",'),
    code(' "timestamp": "2026-03-26T08:14:22Z",'),
    code(' "board_name": "QCI Board",'),
    code(' "application_id": "NABH-2025-00412",'),
    code(' "organisation_name": "City General Hospital",'),
    code(' "programme_name": "NABH Hospital Accreditation",'),
    code(' "stage_name": "Document Review",'),
    code(' "changed_by": "officer@qci.org.in"}'),
    spacer(),

    h2("Webhook Payload — Email Sent"),
    code('{"event": "email_sent",'),
    code(' "timestamp": "2026-03-26T08:01:14Z",'),
    code(' "notification_type": "R1",'),
    code(' "application_id": "NABH-2025-00412",'),
    code(' "to_email": "priya.sharma@cityhospital.in"}'),
    spacer(),

    h2("Webhook Reliability Notes"),
    bullet("10-second send timeout per webhook"),
    bullet("Failed webhooks are NOT retried automatically — failure is logged in audit log"),
    bullet("Your endpoint should respond within 5 seconds; use async queue for longer processing"),
    bullet("No HMAC signing currently — verify by cross-referencing expected events"),
    spacer(),

    pageBreak(),
    h1("6. Error Codes and Troubleshooting"),
    dataTable(["Status Code","Meaning"],[
      ["200 OK","Request succeeded"],
      ["400 Bad Request","Missing or invalid request body fields"],
      ["401 Unauthorized","API key missing, invalid, or revoked"],
      ["403 Forbidden","API key does not have access to the requested resource"],
      ["404 Not Found","Case, stage, or programme does not exist"],
      ["422 Unprocessable Entity","Valid JSON but semantically invalid data"],
      ["500 Internal Server Error","Unexpected server-side error"],
      ["503 Service Unavailable","Service starting up (cold start) or DB unreachable"],
    ]),
    spacer(),

    h2("Common Errors"),
    dataTable(["Error","Cause","Fix"],[
      ['"Invalid or missing API key" (401)',"Header missing, typo, or key revoked","Check X-API-Key header spelling; verify key is active on /api-keys"],
      ['"Stage not found" (404)',"stage_name doesn't match exactly","Check capitalisation and spacing in Settings → Programmes"],
      ['"Programme not found" (404)',"Programme doesn't exist or wrong board","Ask board admin to create it; verify programme name exactly"],
      ["Cold start delay (503/timeout)","Render free tier idle suspend","Implement retry with exponential backoff; first request after idle takes 20–30s"],
      ["Date parsing error (400)","Ambiguous date format","Use YYYY-MM-DD format exclusively"],
    ]),
    spacer(),

    pageBreak(),
    h1("7. Integration Patterns"),
    h2("Pattern 1: Push Updates from Your System"),
    body("Your system calls POST /api/v1/cases/advance whenever an application moves to a new stage. QCI Engine manages all notifications for that stage."),
    code("Hospital MIS → POST /api/v1/cases/advance → QCI Engine → Automated emails"),
    spacer(),
    tip("Store the API key in an environment variable or secrets manager — never hardcode it in source code."),
    spacer(),

    h2("Pattern 2: Periodic Sync"),
    body("If your system doesn't support event-driven updates, schedule a job every 15 minutes that fetches cases changed since the last sync and calls POST /api/v1/cases/advance for each."),
    tip("Use a last_synced_at timestamp in your system to fetch only recent changes — avoid syncing all cases on every run."),
    spacer(),

    h2("Pattern 3: Read-Back Verification"),
    body("After advancing a case, call GET /api/v1/cases/:app_id to confirm the advance succeeded and verify TAT status. Useful for reconciliation jobs."),
    spacer(),

    h2("Pattern 4: Monitoring Overdue Cases"),
    body("Poll GET /api/v1/cases?status=Active periodically and filter for is_overdue: true to build a secondary dashboard or trigger your own alerts in your system."),
    spacer(),

    h2("Pattern 5: Initial Data Migration"),
    body("For initial setup, use the Bulk Upload feature (web interface at /bulk-upload) to import all historical cases from a spreadsheet. Switch to the API for ongoing updates after the initial import."),
    spacer(),

    pageBreak(),
    h1("8. Bulk Upload Format Reference"),
    body("Bulk upload is via the web interface only (/bulk-upload) — there is no API endpoint. This section documents the format so you can prepare data programmatically."),
    spacer(),

    h2("Required Columns"),
    dataTable(["Column Name","Description","Example"],[
      ["Application_ID","Your unique identifier","NABH-2025-00412"],
      ["Organisation_Name","Organisation name","City General Hospital"],
      ["Programme_Name","Exact programme name (case-sensitive)","NABH Hospital Accreditation"],
      ["Stage_Name","Exact stage name (case-sensitive)","Document Review"],
      ["Date_of_Stage_Change","When stage began (YYYY-MM-DD recommended)","2026-03-20"],
      ["Action_Owner_Name","Full name of action owner","Dr. Priya Sharma"],
      ["Action_Owner_Email","Action owner's email","priya.sharma@hospital.in"],
      ["Program_Officer_Email","Program officer's email","officer@qci.org.in"],
    ]),
    spacer(),

    h2("Optional Columns"),
    dataTable(["Column Name","Description"],[
      ["CC_Emails","Comma-separated CC recipients for all notifications on this case"],
    ]),
    spacer(),

    h2("Common Mistakes"),
    dataTable(["Mistake","Symptom","Fix"],[
      ["Programme/Stage name mismatch","Row fails: 'not found'","Copy names exactly from Settings page"],
      ["Ambiguous date (01/02/2026)","Wrong date parsed","Use YYYY-MM-DD exclusively"],
      ["Missing required column","Entire upload rejected","Download fresh template; don't remove columns"],
      ["Extra whitespace in emails","Notification delivery fails","Trim all whitespace from email fields"],
      ["Duplicate Application_ID in file","Second row silently overwrites first","Deduplicate before uploading"],
    ]),
    spacer(300),
  ];

  return new Document({ numbering, styles, sections: [{ properties: { page: pageProps }, headers: { default: makeHeader() }, footers: { default: makeFooter() }, children }] });
}

// ════════════════════════════════════════════════════════════════════
// DOCUMENT 3: USER GUIDE
// ════════════════════════════════════════════════════════════════════
function buildUserGuide() {
  const children = [
    logoBlock("Complete User Guide"),
    spacer(200),
    body("Version: 1.0   |   System URL: https://web-production-c0ec0.up.railway.app   |   Last Updated: 30 March 2026", { color: QCI_GREY }),
    body("For all users, including those new to the system.", { italics: true, color: QCI_GREY }),
    spacer(100),

    h1("1. What Is This System?"),
    body("The QCI Notification Engine is a tool for tracking applications or cases through a step-by-step process — and making sure nothing falls behind schedule."),
    body("Imagine you are managing dozens of hospitals going through an accreditation process. Each hospital (a \"case\") has to pass through several steps — submitting documents, getting assessed, undergoing an audit, and so on. Each step has a deadline. If a step is taking too long, someone needs to be reminded."),
    spacer(),
    body("That is exactly what this system does:"),
    bullet("Keeps a list of all cases and which step each one is currently on"),
    bullet("Tracks how many days each step has been going on"),
    bullet("Automatically sends email reminders to the right people before a deadline is missed"),
    bullet("Sends overdue alerts if deadlines are missed, and escalates to a manager after a set number of days"),
    bullet("Gives managers a weekly summary of where everything stands"),
    spacer(),
    tip("You do not need to send reminder emails manually or track spreadsheets. The system does it for you."),
    spacer(),

    h1("2. How to Log In"),
    ...screenshotPlaceholder("Screenshot: Login Page"),
    h2("Steps"),
    numbered("Open your web browser (Chrome, Firefox, Edge, or Safari)"),
    numbered("Go to: https://web-production-c0ec0.up.railway.app"),
    numbered("Enter your username and password"),
    numbered("Click the Log In button"),
    numbered("If 2FA is enabled, enter the 6-digit code from your authenticator app and click Verify"),
    numbered("You will land on your dashboard"),
    spacer(),

    h2("First-Time Login"),
    body("Your administrator will have given you a temporary username and password. After logging in you may be redirected to a Change Your Password page. Enter a new password (at least 8 characters), confirm it, and save. Use your new password from then on."),
    spacer(),

    h2("If You Forget Your Password"),
    warning("There is no self-service 'Forgot Password' link. Contact your Board Admin or Super Admin to reset your password."),
    spacer(),

    h2("If the System Seems Slow"),
    body("The system may take up to 30 seconds to load after a period of inactivity — this is normal for the cloud hosting plan. Just wait, and it will appear. After the first load it will be fast."),
    spacer(),

    h1("3. The Dashboard"),
    ...screenshotPlaceholder("Screenshot: Dashboard Overview — full view"),
    body("After logging in you will see the main dashboard — a table showing all the cases you have access to."),
    spacer(),

    h2("What Each Column Means"),
    dataTable(["Column","What It Shows"],[
      ["Application ID","A unique code for each case (e.g., NABH-2025-00412)"],
      ["Organisation","The name of the organisation this case belongs to"],
      ["Programme","The type of process this case is going through"],
      ["Current Stage","The step the case is currently at"],
      ["Stage Start Date","When this step began"],
      ["Days Elapsed","How many working days have passed since this step started"],
      ["TAT (Days)","The target number of days this step should take"],
      ["Days Remaining","Days left before the deadline (negative = already overdue)"],
      ["TAT Status","Colour-coded label: on track / approaching / overdue"],
      ["Action Owner","The person responsible for completing this step"],
      ["Status","Active / On Hold / Closed / Withdrawn / Suspended"],
    ]),
    spacer(),

    h2("Colour Coding"),
    ...screenshotPlaceholder("Screenshot: Dashboard — colour coding (green/amber/red rows)"),
    dataTable(["Colour","Meaning"],[
      ["Green","On track — the deadline is not close yet"],
      ["Amber / Orange","Approaching the deadline — a reminder has been or will soon be sent"],
      ["Red","Overdue — the deadline has passed, an overdue alert has been sent"],
      ["Grey","Case is not active (On Hold / Closed) — TAT tracking is paused"],
    ]),
    spacer(),

    h2("Navigating the Dashboard"),
    bullet("Use the search bar at the top to find a case by Application ID or organisation name"),
    bullet("Use filter dropdowns to narrow by programme, stage, or status"),
    bullet("Click any Application ID to see the full history of that case"),
    bullet("Use page arrows at the bottom to move between pages"),
    spacer(),

    pageBreak(),
    h1("4. Guide by Role"),
    h2("4.1 Program Officer"),
    body("You are the main day-to-day user. You add cases to the system, move them forward as they progress through stages, and manage them throughout their journey."),
    spacer(),
    body("What you can do:"),
    bullet("Add new cases using the Log Stage form"),
    bullet("Move a case to the next stage when work is complete"),
    bullet("Edit case details (e.g., update the action owner's email)"),
    bullet("Put a case on hold, close it, or mark it as withdrawn"),
    bullet("Search and filter cases"),
    bullet("Export case data to Excel or CSV"),
    bullet("Upload multiple cases at once using a spreadsheet"),
    spacer(),
    body("Your typical daily workflow:"),
    numbered("A new application comes in — log it under the right programme and stage"),
    numbered("As the case progresses, advance it to the next stage"),
    numbered("The system automatically sends reminders to the action owner"),
    numbered("Check the dashboard to see which cases are approaching deadlines or overdue"),
    spacer(),

    h2("4.2 Program Head"),
    body("You oversee cases in your programme. You receive important alerts and can view the status of all cases."),
    spacer(),
    body("What you can do:"),
    bullet("View the dashboard filtered to your programme's cases"),
    bullet("See case histories"),
    bullet("Receive escalation emails when a case has been overdue for too long"),
    spacer(),
    tip("When you receive an escalation email, contact the program officer or action owner for that case to find out why it is delayed."),
    spacer(),

    h2("4.3 Board CEO"),
    body("You have a high-level, read-only view. Your role is to monitor overall progress without getting into the details."),
    spacer(),
    body("What you can do:"),
    bullet("View the CEO Dashboard (a simplified summary view)"),
    bullet("Receive Weekly Digest emails every Monday morning"),
    spacer(),
    body("The Weekly Digest email (sent every Monday at 8:00 AM) contains:"),
    bullet("How many cases are active across each programme"),
    bullet("How many cases are overdue"),
    bullet("How many cases are nearing their deadlines"),
    bullet("Cases on hold or suspended"),
    spacer(),
    tip("You do not need to log in unless you want to drill down into specific cases. The digest email gives you the weekly summary."),
    spacer(),

    h2("4.4 Board Admin"),
    body("You set up and manage your board's configuration. This is an administrative role."),
    spacer(),
    body("What you can do:"),
    bullet("Create and manage programmes"),
    bullet("Set up stages with TAT, reminder thresholds, and email configuration"),
    bullet("Customise email templates"),
    bullet("Configure SMTP settings (the email server)"),
    bullet("Manage users on your board (create, reset passwords, assign roles)"),
    bullet("View the audit log"),
    spacer(),
    body("Getting started as a new Board Admin:"),
    numbered("Log in and go to Settings"),
    numbered("Set up your SMTP email configuration"),
    numbered("Create your programmes and add stages to each"),
    numbered("Set the TAT and reminder days for each stage"),
    numbered("Customise email templates if needed (defaults are provided)"),
    numbered("Create user accounts for your team"),
    spacer(),

    h2("4.5 Super Admin"),
    body("You have full control over the entire system."),
    spacer(),
    body("Additional capabilities beyond Board Admin:"),
    bullet("Manage all boards and their settings"),
    bullet("Configure system-wide settings (scheduler time, digest, escalation days)"),
    bullet("Create and revoke API keys for technical integrations"),
    bullet("View full audit log across all boards"),
    bullet("Trigger a manual scheduler run"),
    bullet("Test SMTP connectivity"),
    spacer(),
    body("System Settings you control:"),
    dataTable(["Setting","What It Does"],[
      ["Scheduler time","What time each day the system checks for overdue cases and sends emails (default 8:00 AM IST)"],
      ["Digest enabled","Whether weekly summary emails are sent at all"],
      ["Escalation days","How many days overdue before escalating to Program Head"],
      ["Webhook URL","Notifies an external system when cases change"],
    ]),
    spacer(),

    pageBreak(),
    h1("5. How to Add a Case"),
    ...screenshotPlaceholder("Screenshot: Log Stage Form"),
    body("'Adding a case' means logging that a new application has entered a stage in a programme."),
    spacer(),
    numbered("Make sure you are logged in as a Program Officer or Board Admin"),
    numbered("Click Log Stage in the sidebar or navigation bar"),
    numbered("Fill in the form:"),
    spacer(),
    dataTable(["Field","What to Enter"],[
      ["Application ID","Your unique code for this application (e.g., NABH-2025-00412). Must match your other records."],
      ["Organisation Name","The organisation's name (e.g., the hospital's name)"],
      ["Programme","Select from dropdown. If not listed, ask your Board Admin to create it."],
      ["Stage","Select the stage this case is currently at. Options update based on programme."],
      ["Date of Stage Change","When this stage began. Type or use the date picker."],
      ["Action Owner Name","Full name of the person responsible for completing this stage"],
      ["Action Owner Email","Their email. They will receive reminder emails."],
      ["Program Officer Email","Email of the program officer for this case"],
      ["CC Emails (optional)","Other people who should receive copies of notification emails"],
    ]),
    spacer(),
    numbered("Click Save or Submit"),
    numbered("The case now appears on the dashboard"),
    spacer(),
    warning("Double-check all email addresses before saving. Incorrect emails mean the right people won't get their reminders."),
    spacer(),

    h1("6. How to Advance a Case to the Next Stage"),
    body("When a stage is complete and the case needs to move forward, you 'advance' it. This updates the case to a new stage and resets the deadline tracking."),
    spacer(),

    h2("Method 1: Quick Advance from Dashboard"),
    ...screenshotPlaceholder("Screenshot: Quick Advance Modal"),
    numbered("Find the case in the dashboard"),
    numbered("Click the Quick Advance button (usually a forward arrow icon on the row)"),
    numbered("Select the next stage from the dropdown"),
    numbered("Enter the Stage Start Date"),
    numbered("Update Action Owner details if the responsible person has changed"),
    numbered("Click Confirm"),
    spacer(),

    h2("Method 2: Bulk Advance (Multiple Cases)"),
    numbered("On the dashboard, tick the checkboxes next to the cases you want to advance"),
    numbered("Click Bulk Advance at the top of the table"),
    numbered("Select the stage, enter the date, and confirm"),
    spacer(),

    body("After advancing a stage:"),
    bullet("The case's current stage updates on the dashboard"),
    bullet("Notification flags reset — the system tracks deadlines for the new stage"),
    bullet("A record is added to the case history"),
    bullet("If a webhook is configured, the external system is notified"),
    spacer(),

    pageBreak(),
    h1("7. Bulk Upload"),
    ...screenshotPlaceholder("Screenshot: Bulk Upload Page"),
    h2("When to Use It"),
    body("Use bulk upload when you need to add or update many cases at once:"),
    bullet("Starting a new programme with many organisations already in different stages"),
    bullet("Importing historical data from a spreadsheet"),
    bullet("Updating a batch of cases that all moved to a new stage on the same day"),
    spacer(),
    tip("For day-to-day work (one or two cases at a time), use the Log Stage form instead."),
    spacer(),

    h2("How to Use Bulk Upload"),
    numbered("Go to Bulk Upload in the navigation"),
    numbered("Click Download CSV Template or Download Excel Template"),
    numbered("Open the template in Excel or Google Sheets"),
    ...screenshotPlaceholder("Screenshot: Bulk Upload — filled template example"),
    numbered("Fill in one row per case. Do not change the column headings."),
    numbered("Save the file"),
    numbered("On the Bulk Upload page, click Choose File and select your saved file"),
    numbered("Click Upload"),
    numbered("Review the results — how many rows succeeded and how many failed (with error details)"),
    spacer(),

    h2("Column Reference"),
    dataTable(["Column","Required?","What to Enter"],[
      ["Application_ID","Yes","Your unique code for this application"],
      ["Organisation_Name","Yes","Organisation name"],
      ["Programme_Name","Yes","Must match exactly a programme in the system"],
      ["Stage_Name","Yes","Must match exactly a stage in that programme"],
      ["Date_of_Stage_Change","Yes","Date the stage began — use YYYY-MM-DD format"],
      ["Action_Owner_Name","Yes","Full name of the action owner"],
      ["Action_Owner_Email","Yes","Email of the action owner"],
      ["Program_Officer_Email","Yes","Email of the program officer"],
      ["CC_Emails","No","Extra emails to CC (comma-separated)"],
    ]),
    spacer(),

    h2("Common Mistakes to Avoid"),
    warning("Programme and Stage names must match exactly — even a trailing space or different capitalisation will cause that row to fail. Copy the names directly from the Settings page."),
    spacer(),
    bullet("Use the YYYY-MM-DD date format (e.g., 2026-03-20) — other formats can be misread"),
    bullet("Do not leave required columns blank"),
    bullet("Do not add extra columns or rename existing ones"),
    bullet("Remove any test or sample rows from the template before uploading"),
    bullet("Check email addresses for typos"),
    spacer(),

    pageBreak(),
    h1("8. Searching and Filtering"),
    ...screenshotPlaceholder("Screenshot: Search and Filter Bar"),
    h2("Quick Search"),
    body("Use the search bar at the top of the dashboard to find a case by Application ID, organisation name, or stage name. Type a few letters and matching cases will appear."),
    spacer(),

    h2("Using Filters"),
    numbered("Look for the filter controls above the dashboard table"),
    numbered("Filter by: Programme, Stage, Status, or TAT Status (overdue / approaching / on track)"),
    numbered("Select your options and the table updates automatically"),
    spacer(),

    h2("Saving a Filter"),
    body("If you use the same filters regularly:"),
    numbered("Set up your filters as usual"),
    numbered("Click Save Filter and give it a name"),
    numbered("Your saved filter appears in the filter menu for quick access next time"),
    spacer(),

    h2("Viewing a Case's Full History"),
    ...screenshotPlaceholder("Screenshot: Case History Timeline"),
    body("Click on any Application ID in the dashboard to open its full case history page. This shows every stage the case has been through, who made each change, and when."),
    spacer(),

    pageBreak(),
    h1("9. Understanding Email Notifications"),
    body("The system automatically sends emails based on how cases are progressing. You do not need to send these manually."),
    spacer(),

    dataTable(["Email Type","When It's Sent","Who Receives It"],[
      ["R1 — First Reminder","A set number of days before the stage deadline (e.g., 7 days before)","Action owner + Program officer"],
      ["R2 — Second Reminder","Closer to the deadline (e.g., 3 days before) — more urgent","Action owner + Program officer"],
      ["Overdue","The day after the deadline passes","Action owner + Program officer"],
      ["Followup","Every few days while the case remains overdue","Action owner + Program officer + Program Head (after escalation threshold)"],
      ["Weekly Digest","Every Monday at 8:00 AM","Board CEO + Program Heads"],
    ]),
    spacer(),
    ...screenshotPlaceholder("Screenshot: Weekly Digest Email example"),
    spacer(),

    h2("What If an Email Was Not Sent?"),
    numbered("Check your spam / junk folder first"),
    numbered("Ask your Board Admin to check the Email Queue page"),
    numbered("If an email failed, the admin can retry it from that page"),
    numbered("Verify the email address on the case is correct (no typos)"),
    spacer(),

    pageBreak(),
    h1("10. Exporting Data"),
    ...screenshotPlaceholder("Screenshot: Export Page with filters"),
    h2("Exporting to CSV"),
    body("A CSV file can be opened in Excel or Google Sheets."),
    numbered("Go to the dashboard"),
    numbered("Apply any filters you want"),
    numbered("Click Export or Export CSV"),
    numbered("Your browser downloads the file automatically"),
    spacer(),

    h2("Exporting to Excel (XLSX)"),
    body("The Excel export contains four sheets:"),
    bullet("Cases — all case data with current status"),
    bullet("Stage History — every stage transition for every case"),
    bullet("Audit Log — record of every action in the system"),
    bullet("TAT Summary — turnaround time performance by programme"),
    spacer(),
    numbered("Go to the dashboard or Export page in the navigation"),
    numbered("Click Export to Excel"),
    numbered("For large datasets, the file is prepared in the background — you will be notified when ready"),
    numbered("Click Download when it appears"),
    spacer(),
    tip("Apply filters before exporting to get only the data you need — smaller exports are faster. Excel format is best for management reports; CSV is best for importing into another system."),
    spacer(),

    pageBreak(),
    h1("11. Case Statuses Explained"),
    body("Every case has a Status that tells you where it stands. Here is what each means and when to use it."),
    spacer(),

    dataTable(["Status","What It Means","When to Use It"],[
      ["Active","Case is progressing normally. Deadlines tracked, notifications sent.","Default for any case being actively worked on"],
      ["On Hold","Work temporarily paused. No reminders sent while on hold.","Valid reason for pause: organisation requested suspension, waiting for external input"],
      ["Closed","Successfully completed. All stages done, process finished.","Organisation has completed the full programme"],
      ["Withdrawn","Organisation withdrew their application voluntarily.","Organisation asked to exit the process"],
      ["Suspended","Formally suspended by board decision.","Pending investigation or following a board decision"],
    ]),
    spacer(),
    warning("Changing a case to any status other than Active pauses all notification emails. When changing back to Active, update the Stage Start Date to recalculate TAT correctly."),
    spacer(),

    pageBreak(),
    h1("12. Frequently Asked Questions"),
    spacer(),

    h2("Q1: I logged in but the dashboard is empty. Where are my cases?"),
    body("You may have active filters that return no results, or your account may not be assigned to the correct board. Clear all filters. If still empty, contact your Board Admin — they may need to assign you to the correct board or programme."),
    spacer(),

    h2("Q2: I made a mistake when logging a case. How do I fix it?"),
    body("Find the case on the dashboard, click its Application ID, and use the Edit Case option. You can update organisation name, action owner details, email addresses, and stage start date. You cannot undo a stage advance — contact your Board Admin if you advanced to the wrong stage."),
    spacer(),

    h2("Q3: The action owner says they did not receive the reminder email."),
    numbered("Ask them to check their spam or junk folder"),
    numbered("Verify the action owner's email on the case has no typos"),
    numbered("Ask your Board Admin to check the Email Queue page"),
    numbered("The admin can retry failed emails from that page"),
    spacer(),

    h2("Q4: A case has been sitting at a stage for months. How do I close it?"),
    body("Find the case, click on it, and change the Status to Closed or Withdrawn as appropriate. The system will stop sending notifications immediately."),
    spacer(),

    h2("Q5: I uploaded a bulk file and some rows failed. What do I do?"),
    body("After uploading, the results screen shows which rows failed and why (e.g., 'Stage not found' or 'Invalid date'). Correct those rows in your spreadsheet and re-upload only the failed rows."),
    spacer(),

    h2("Q6: Can I change the deadline (TAT) for a stage?"),
    body("TAT is set by your Board Admin in Settings. Contact your admin to update it. Note: changing TAT applies to future cases only, not cases already in progress."),
    spacer(),

    h2("Q7: I need to add a new programme. How?"),
    body("Only a Board Admin can create programmes and stages. Contact your Board Admin with the programme details: name, stages, and TAT for each stage."),
    spacer(),

    h2("Q8: What time does the system send reminder emails?"),
    body("By default, 8:00 AM Indian Standard Time every day. Your Super Admin can change this in System Settings."),
    spacer(),

    h2("Q9: I cannot see cases from another programme. Is that normal?"),
    body("Yes. Program Officers can only see cases in the programmes assigned to their board. Contact your Board Admin if you need access to additional programmes."),
    spacer(),

    h2("Q10: How do I know if a case has already been notified?"),
    body("Click the case's Application ID to open its detail view. You will see flags showing whether R1, R2, or Overdue emails have been sent for the current stage, and the date of the last followup."),
    spacer(),

    h2("Q11: I received an escalation email. What am I supposed to do?"),
    body("An escalation email means a case has been overdue for a significant number of days. Contact the program officer or action owner for that case to find out why it is delayed. Once resolved, the program officer can advance the case or update its status."),
    spacer(),

    h2("Q12: Can two people have the same username?"),
    body("No. Usernames must be unique. If you try to create a user with a name that already exists, the system will show an error."),
    spacer(),

    h2("Q13: Do programme names have to match exactly?"),
    body("Yes. For bulk upload and API integration, programme and stage names must match exactly what is configured in the system — including capitalisation and spacing. Ask your Board Admin if you need to align naming conventions."),
    spacer(),

    h2("Q14: I see a Delete Case option. Should I use it?"),
    warning("Deleting a case is permanent and removes all its history. Only delete cases added by mistake (test entries, duplicates). For cases that are finished or withdrawn, use the Closed or Withdrawn status instead."),
    spacer(),

    body("For further assistance, contact your Board Admin. For technical issues, contact your Super Admin or the system administrator at your organisation.", { color: QCI_GREY, italics: true }),
    spacer(300),
  ];

  return new Document({ numbering, styles, sections: [{ properties: { page: pageProps }, headers: { default: makeHeader() }, footers: { default: makeFooter() }, children }] });
}

// ── Generate all three docs ───────────────────────────────────────
async function main() {
  const docs = [
    { name: "System_Information.docx", doc: buildSystemDoc() },
    { name: "API_Documentation.docx",  doc: buildApiDoc() },
    { name: "User_Guide.docx",         doc: buildUserGuide() },
  ];
  for (const { name, doc } of docs) {
    const buf = await Packer.toBuffer(doc);
    fs.writeFileSync(`/Users/anoushka/Documents/qci_notifications/docs/${name}`, buf);
    console.log(`✅ Written: ${name} (${(buf.length / 1024).toFixed(0)} KB)`);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
