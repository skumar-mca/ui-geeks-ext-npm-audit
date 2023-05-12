const { writeFile } = require('fs');
const { posix } = require('path');
const { window, ViewColumn, workspace, Uri } = require('vscode');

const {
  COMMON_CSS,
  REPORT_FILE_NAME,
  REPORT_FOLDER_NAME,
  REPORT_TITLE,
  MSGS
} = require('./constants');
const { logMsg, logErrorMsg } = require('./util');

class WebRenderer {
  template = null;
  title = '';
  panel = null;
  context = null;
  content = null;
  appMeta = null;
  reportData = null;

  constructor(template, title) {
    this.title = title;
    this.template = template;
  }

  get applicationName() {
    if (this.appMeta) {
      return this.appMeta.appName;
    }
    return null;
  }

  init = async (context) => {
    this.context = context;
    this.initializePanel();
    this.onClosePanel();
  };

  initializePanel = () => {
    this.panel = createPanel(this.title);

    // Handle messages from the webview
    this.panel.webview.onDidReceiveMessage(
      (message) => {
        switch (message.command) {
          case 'downloadReportAsHTML':
            this.createReport('html');
            return;
        }
      },
      undefined,
      this.context.subscriptions
    );
  };

  sendMessageToUI = (msg) => {
    this.panel.webview.postMessage({ command: msg });
  };

  createReport = (reportType) => {
    createReportFile(this, this.content, reportType);
  };

  onClosePanel = () => {
    this.panel.onDidDispose(() => {}, null);
  };

  renderContent = (content) => {
    const vulnerabilityStr = `
    <div>
      <div class='flex'>
        <div class='text-center'>
          <h2>Vulnerabilities (${this.reportData.totalVulnerabilities})</h2>
          <div style="width: 300px;">
            <canvas id="vulnerabilities"></canvas>
          </div>
        </div>
    
        <div class='text-center'>
          <h2>Dependencies (${this.reportData.totalDependencies})</h2>
          <div style="width: 300px;">
            <canvas id="dependencies"></canvas>
          </div>
        </div>
      </div>
      <br />
      <div style="border-bottom: 1px solid #8b8989; margin-bottom: 15px"></div>
      <script>
      const chartOptions = {
            animations: false,
            plugins: {
                legend: {
                    position:'bottom',
                    labels: {
                        font:{ size: 16}
                    }
                }
            }
      };
    
      function showVulnerabilityChart() {
      const data = {
        labels: ['Critical (${this.reportData.critical})', 'High (${this.reportData.high})', 'Moderate (${this.reportData.moderate})','Low (${this.reportData.low})','Info (${this.reportData.info})'],
        datasets: [
          {
            label: 'Vulnerabilities',
            data: [${this.reportData.vulChartDataList}],
            backgroundColor: ['#ff2f2f','#f77a7a','#958138','#4ecd86','#6da4dd'],
          }
        ]
      };
    
      const config = {
        type: 'doughnut',
        data: data,
        options: chartOptions
      };
    
      new Chart(document.getElementById('vulnerabilities'), config);
      }
    
      function showDependencyChart() {
      const data = {
        labels: ['Dev (${this.reportData.dev})', 'Prod (${this.reportData.prod})', 'Optional (${this.reportData.optional})','Peer (${this.reportData.peer})','Peer Optional (${this.reportData.peerOptional})'],
        datasets: [
          {
            label: 'Dependencies',
            data: [${this.reportData.depChartDataList}],
            backgroundColor: ['#958138','#4ecd86','#6da4dd','#f77a7a','#7a7979'],
          }
        ]
      };
    
      const config = {
        type: 'doughnut',
        data: data,
        options: chartOptions
      };
    
      new Chart(document.getElementById('dependencies'), config);
      }
    
      showVulnerabilityChart();
      showDependencyChart();
      </script>
      <br />
    </div>`;

    const noVulnerabilityStr = `
    <div class='no-vul'>
      <div class='head'>Great! No vulnerabilities found.</div>
      <div class='sub-head'>All packages are safe to use.</div>
    </div>`;

    const htmlStr = `<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${REPORT_TITLE}${
      this.applicationName ? ` - ${this.applicationName}` : ''
    }</title>
        <style>
          ${COMMON_CSS}
          .table-dep { margin-bottom:40px; }
          .table-dep th:nth-child(3){ width: 120px;}
          .no-vul { padding: 20px; background: #7bb134; text-align: center; height: 150px; display: flex; align-items: center; flex-direction: column; justify-content: center; color: #242020;}
          .no-vul .head { font-size: 40px; font-weight:bold;}
          .no-vul .sub-head { font-size: 20px; margin-top:10px;}
        </style>
        <script
          src="https://cdn.jsdelivr.net/npm/chart.js@4.2.1/dist/chart.umd.min.js"
          type="text/javascript"
        ></script>
    </head>

    
    <script>
        const vscode = acquireVsCodeApi();
        function downloadReport(reportType) {
          vscode.postMessage({
              command: reportType === 'html' ? 'downloadReportAsHTML' : 'downloadReportAsPDF' ,
              text: 'Download Report Now'
          })
        }

      window.addEventListener('message', (event) => {
        const message = event.data;
        const downloadBtn = document.getElementById('downloadLink');

        switch (message.command) {
          case 'downloadingStart':
            
            if (downloadBtn) {
              downloadBtn.textContent = 'Downloading...';
            }
            break;

          case 'downloadingEnd':
            if (downloadBtn) {
              downloadBtn.textContent = 'Download as';
            }
            break;
        }
      });
    </script>

    <body>
      <div style="display: flex">
        <h1 class="header">
          <h2 class="header">
            NPM Audit Report
            <span class='email-link header-link-actions'>
              <span class='color-grey'> <span id='downloadLink'>Download as</span>&nbsp;<a class='no-link' href='javascript:void(0)' title='Download Report in HTML Format' onclick="downloadReport('html')">HTML</a>
              </span>
            </span>
          </h2>
        </h1>
      </div>

      <div style="border-bottom: 1px solid #8b8989; margin-bottom: 15px"></div>

      <div class="content">
          <div class="content-box box box-grey">
            <div class="field-label">Application Name</div>
            <div class="field-value">${this.appMeta.appName}</div>
          </div>

          <div class="content-box box box-grey">
            <div class="field-label">Version</div>
            <div class="field-value">${this.appMeta.appVersion}</div>
          </div>

          <div class="content-box box box-grey">
            <div class="field-label">Description</div>
            <div class="field-value">${this.appMeta.appDescription}</div>
          </div>

          <div class="content-box box box-grey">
            <div class="field-label">Packages Used</div>
            <div class="field-value">${this.appMeta.appTotalDep}</div>
          </div>
        </div>
      <br/>

      ${
        this.reportData.totalVulnerabilities > 0
          ? vulnerabilityStr
          : noVulnerabilityStr
      }


      ${content}

    </body>
    </html>`;

    this.content = htmlStr;
    renderContentOnPanel(this.panel, htmlStr);
  };

  renderLoader = () => {
    renderLoader(this, this.panel, this.title);
  };

  renderError = (meta) => {
    renderError(this, this.panel, meta);
  };

  setAppMetaData = (appData) => {
    this.appMeta = appData;
  };

  setReportData = (data) => {
    this.reportData = data;
  };
}

const createPanel = (title) => {
  return window.createWebviewPanel(
    title.replace(' ', '').trim(),
    title,
    ViewColumn.One,
    { localResourceRoots: [], enableScripts: true }
  );
};

const renderContentOnPanel = (panel, content) => {
  panel.webview.html = content;
};

const renderLoader = async (_this, panel, title) => {
  const content = `<!DOCTYPE html>
  <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${REPORT_TITLE}${
    _this.applicationName ? ` - ${_this.applicationName}` : ''
  }</title>
        <style>
          ${COMMON_CSS}
        </style>
   </head>
  
    <body>
      <h1 class="header">${title}</h1>
      <div style="border-bottom: 1px solid #8b8989; margin-bottom: 15px"></div>
      <div>Running ${title}...</div>
      <br />
    </body>
  </html>
`;

  renderContentOnPanel(panel, content);
};

const renderError = async (_this, panel, meta) => {
  const { actionHeader, hasSolution, message } = meta;

  const content = `<!DOCTYPE html>
  <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${REPORT_TITLE}${
    _this.applicationName ? ` - ${_this.applicationName}` : ''
  }</title>
        <style>
          ${COMMON_CSS}
          body{ background: #ffa9a9; color:black; }
        </style>
   </head>
  
    <body>
      <h1 class="header">${actionHeader} Failed</h1>
      <div style="border-bottom: 1px solid #8b8989; margin-bottom: 15px;"> </div>
      <br/>
  
      <div class="text-danger b mb-2">${
        message || 'Something went wrong, please try again after sometime.'
      }</div>
  
      ${hasSolution ? `<div class="box box-info">${hasSolution}</div>` : ''}
    </body>
  </html>
`;

  _this.content = content;
  panel.webview.html = content;
};

const createReportFile = async (webRenderedRef, content, reportType) => {
  const folderUri = workspace.workspaceFolders[0].uri;

  const reportFileName = posix.join(
    folderUri.path,
    `${REPORT_FOLDER_NAME}/${REPORT_FILE_NAME}`
  );

  try {
    webRenderedRef.sendMessageToUI('downloadingStart');
    content += `<style>.header-link-actions { display: none;} body, table { font-size:12px!important;}</style>`;
    let fileUri = folderUri.with({ path: `${reportFileName}.${reportType}` });
    let filters = null;
    let reportContent = content;
    let saveDialogTitle = `Save ${REPORT_TITLE}`;

    switch (reportType) {
      case 'html':
        filters = { WebPages: ['html'] };
        break;
    }

    if (filters) {
      if (webRenderedRef.appMeta) {
        fileUri = folderUri.with({
          path: `${reportFileName}-${webRenderedRef.appMeta.appName}.${reportType}`
        });

        saveDialogTitle = `Save ${REPORT_TITLE} for ${
          webRenderedRef.appMeta.appName || 'Application'
        }`;
      }

      const uri = await window.showSaveDialog({
        filters,
        defaultUri: fileUri,
        saveLabel: `Save Report`,
        title: saveDialogTitle
      });

      if (!uri) {
        webRenderedRef.sendMessageToUI('downloadingEnd');
      }

      writeFile(uri.fsPath, reportContent, () => {
        logMsg(MSGS.REPORT_CREATED, true);
        webRenderedRef.sendMessageToUI('downloadingEnd');
      });
    }
  } catch (e) {
    webRenderedRef.sendMessageToUI('downloadingEnd');
    if (reportType === 'pdf') {
      logErrorMsg(MSGS.PDF_ERROR, true);
    }
  }
};

const createFolder = async (folderName) => {
  const workSpaceUri = workspace.workspaceFolders[0].uri;
  const folderUri = Uri.parse(`${workSpaceUri.path}/${folderName}`);
  await workspace.fs.createDirectory(folderUri);
};

module.exports = {
  createPanel,
  renderContentOnPanel,
  renderLoader,
  renderError,
  createFolder,
  WebRenderer
};
