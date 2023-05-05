const extensionPrefix = `ui-geeks-ext-npm-audit`;
const REPORT_TITLE = 'NPM Audit Report';
const REPORT_TEMPLATE = 'npm-audit-report';
const REPORT_FOLDER_NAME = 'ui-geeks-ext-npm-audit';
const REPORT_FILE_NAME = 'npm-audit-report';

const COMMANDS = {
  NPM_AUDIT: `${extensionPrefix}.runNPMAudit`
};

const MSGS = {
  PACKAGE_LOCK_JSON_NOT_FOUND: `Error: package-lock.json file not found!`,
  INVALID_SELECTION: `Invalid Selection`,
  REPORT_PDF_CREATED: `A PDF file named '${REPORT_FILE_NAME}.pdf' is download in folder '${REPORT_FOLDER_NAME}'.\n\n
  Note: Folder will automatically be deleted on closing the '${REPORT_TITLE}' tab.`,
  PDF_ERROR: `Error generating PDF Report. Please try again later. Error: ##MESSAGE##.`,
  PREPARING_PDF: `Generating PDF, please wait...`,
  SCORE_TOOLTIP: `This score calculates overall vulnerability severity from 0 to 10 and is based on the Common Vulnerability Scoring System (CVSS).`,
  CWE_TOOLTIP: `The Common Weakness Enumeration (CWE) is a list of weaknesses in software that can lead to security issues.`,
  GHSA_TOOLTIP: `GHSA is the GitHub Security Advisories database. GHSA ID is the identifier of the advisory for any given vulnerability.`
};

const COLORS = {
  critical: '#ff2f2f',
  high: '#f77a7a',
  moderate: '#958138',
  low: '#4ecd86',
  info: '#6da4dd',
  grey: '#7a7979'
};

const COMMON_CSS = `
:root {
  --critical: #ff2f2f;
  --high: #f77a7a;
  --moderate: #958138;
  --low: #4ecd86;
  --info: #6da4dd;
  --critical-bg: #eb5f3f;
  --high-bg: #f58090;
  --moderate-bg: #cbbb81;
  --low-bg: #93dfb4;
  --info-bg: #b6d3f1;
}

body { font-size: 1em; background-color: #f6f6f6; color: black; -webkit-print-color-adjust: exact;}
.b { font-weight: bold; }
.i { font-style: italic; }
.text-center { text-align:center; }
.text-left { text-align:left; }
.text-right { text-align:right; }
.float-right { float:right; }
.mb-1 { margin-bottom:10px; }
.pl-1 { padding-left:10px; }
.pl-2 { padding-left:20px; }
.mb-2 { margin-bottom:20px; }
.mt-1 { margin-top:10px; }
.mt-2 { margin-top:20px; }
.mr-1 { margin-right:10px; }
.p-2 { padding:20px; }
.color-grey { color: #7a7a7a}
.text-danger{ color:red}
.text-warning { color:#9a5919}
.no-link { text-decoration:none;  }
.no-link:hover { color: #7a7a7a;}
.content { display: flex; flex-direction: row; justify-content: space-between; gap:10px; }
.content-box{ flex:1;} 
.field-label { text-align:center; font-style: italic; }
.field-value { font-weight: bold; text-align:center; }
.header-section { margin-bottom: 0;font-size: 1em;  }
.hint { font-size: 0.9em;font-style: italic; color: #a5a4a4; margin-bottom: 20px; }
.table { width: 100%;max-width: 100%; margin-bottom: 1rem;}
.table th, .table td { padding: 0.75rem;vertical-align: top; border-top: 1px solid #eceeef;background-color: #e7e9eb;color: black;}
.table thead th { vertical-align: bottom; border-bottom: 2px solid #eceeef; text-align: left; }
.table tbody + tbody { border-top: 2px solid #eceeef; }
.table { background-color: #fff; }
.table-sm th,.table-sm td { padding: 0.3rem; vertical-align:center;}
.table-bordered { border: 1px solid #eceeef;}
.table-bordered th, .table-bordered td { border: 1px solid #eceeef;}
.table-bordered thead th, .table-bordered thead td { border-bottom-width: 2px; }
.box{ padding:10px; border:1px solid #c0c0c0; margin-bottom: 20px; border-radius: 4px; background:#c0c0c0; }
.box-critical {background-color: var(--critical)!important; }
.box-high { background-color: var(--high)!important; }
.box-moderate { background-color: var(--moderate)!important; }
.box-low { background-color: var(--low); }
.box-info { background-color: var(--info); }
.box-grey { background-color: var(--info-bg); }
.box-success { background-color: green;}
.compat-update { border-left: 5px solid green; }
.breaking-update { border-left: 5px solid #cf6321; }
.fix-green { color: green; }
.fix-red  { color: red; }
.fix-yellow { color: #cf6321; }
.email-link { font-size:20px; position:absolute; right: 20px; margin-top:20px; }
.email-link a.no-link { font-size:16px; }
.severity-box{ width: 20px; height: 20px; display: inline-block; vertical-align: middle; }
.pill { padding: 2px 10px 2px 10px; border-radius:20px; display:inline-block; }
.badge { padding: 2px 10px 5px 10px; border-radius:4px; display:inline-block; }
.impacted {  margin-top:5px; font-style: italic; color: #787373; float: right; }
.is-indirect {border-left: 3px solid #7e4c0d!important;}
.is-direct {border-left: 3px solid #c79cff!important;}
.is-indirect-indicator { width: 5px; height: 20px; display: inline-block; vertical-align: middle; background-color: #7e4c0d;}
.is-direct-indicator { width: 5px; height: 20px; display: inline-block; vertical-align: middle; background-color: #c79cff;}
.version { background-color: #c0c0c0;}
.flex { display:flex; justify-content: space-around;}
.report-ul { margin-top: 0; margin-bottom: 0; margin-left: 0; padding-inline-start: 25px; }
.report-ul li { margin-bottom:3px; }
`;

module.exports = {
  MSGS,
  extensionPrefix,
  COMMANDS,
  COMMON_CSS,
  REPORT_FILE_NAME,
  REPORT_FOLDER_NAME,
  REPORT_TITLE,
  REPORT_TEMPLATE,
  COLORS
};
