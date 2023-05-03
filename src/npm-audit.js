const { render } = require('mustache');
const { dirname, posix } = require('path');
const util = require('util');
const { window } = require('vscode');
const vscode = require('vscode');
const { findFile, sortByKey } = require('./util');
const {
  MSGS,
  COMMON_CSS,
  REPORT_TEMPLATE,
  REPORT_TITLE
} = require('./constants');
const { WebRenderer, getTemplate } = require('./web-renderer');

const webRenderer = new WebRenderer(REPORT_TEMPLATE, REPORT_TITLE);

const REPORT_UTIL = {
  ifVialsArrayOfObject: (via) => {
    return via.some(({ dependency }) => dependency != null);
  },
  ifViaIsArrayOfString: (via) => {
    return typeof via[0] === 'string';
  },
  ifFixIsBoolean: (fixAvailable) => {
    return typeof fixAvailable === 'boolean';
  },
  ifFixIsObject: (fixAvailable) => {
    return typeof fixAvailable === 'object';
  },
  sortBySeverity: (list) => {
    return sortByKey(list, 'severity');
  },
  sortByDirect: (list, desc) => {
    return sortByKey(list, 'isDirect', desc);
  },
  buildIsDirect: (vul) => {
    return `<div title='${
      vul.isDirect
        ? 'Package is directly dependent'
        : 'Package is not directly dependent, instead any direct dependency is using it'
    }' class='severity-box mr-1 ${
      vul.isDirect ? 'is-direct' : 'is-indirect'
    }'>&nbsp;</div>
`;
  },
  buildIsFixAvailable: (isBooleanFix, vul) => {
    return isBooleanFix
      ? vul.fixAvailable == true
        ? `<div class="fix-green b mt-2">fix available via 'npm audit fix'</div>`
        : `<div class="fix-red b mt-2">No fix available</div>`
      : '';
  },
  buildBreakingFix: (vul) => {
    return REPORT_UTIL.ifFixIsObject(vul.fixAvailable)
      ? `<div class="fix-yellow b mt-2">fix available via 'npm audit fix --force'</div>
    <div><i>Will install <b>${vul.fixAvailable.name}@ ${
          vul.fixAvailable.version
        }</b>
      ${vul.fixAvailable.isSemVerMajor ? ', which is a breaking change' : ''}
      </i>
    </div>`
      : '';
  },
  buildVunerability: (hasDepenciesList, via) => {
    return hasDepenciesList
      ? `<div>Depends on vulnerable versions of <b>${via}</b></div>`
      : `<b>${via.title}</b>${
          via.range
            ? `<br/><div class='impacted'>Impacted Versions: <b>${via.range}</b></div>`
            : ''
        }`;
  },
  buildSeverity: (hasDepenciesList, vul, via) => {
    return `<div class='severity-box box-${
      hasDepenciesList ? vul.severity : via.severity
    }'></div>`;
  },
  buildScore: (via) => {
    return via.cvss && via.cvss.score
      ? `<span ><b>${via.cvss.score}</b></span>`
      : '';
  },
  buildPackage: (vul, isBooleanFix) => {
    return `<div>
              ${REPORT_UTIL.buildPackageName(vul)}
              <div class='float-right badge version'><i>v${vul.range}</i></div>
            </div>
            ${REPORT_UTIL.buildIsFixAvailable(isBooleanFix, vul)}
            ${REPORT_UTIL.buildBreakingFix(vul)}`;
  },
  buildPackageName: (vul) => {
    return `<b><a href='https://www.npmjs.com/package/${vul.name}' class='no-link'>${vul.name}</a></b>`;
  },
  getCWEValue: (cweList) => {
    let cweArr = [];
    if (cweList instanceof Array) {
      cweArr = cweList.map((cwe) => {
        const cweVal = cwe.replace('CWE-', '');
        return `<a href='https://cwe.mitre.org/data/definitions/${cweVal}.html'>${cweVal}</a>`;
      });

      if (cweArr.length > 0) {
        return `${cweArr.join('<br/>')}`;
      }

      return '';
    }
    return '';
  },
  getVulnerabilitiesValue: (vul) => {
    let vulArr = [];
    if (vul.via instanceof Array) {
      const vulnerabilityCount = REPORT_UTIL.getVulnerabilitiesCount(vul);
      const hasDepenciesList = REPORT_UTIL.ifViaIsArrayOfString(vul.via);
      const isBooleanFix = REPORT_UTIL.ifFixIsBoolean(vul.fixAvailable);

      vulArr = vul.via.map((via, index) => {
        return `<tr>
          ${
            index === 0
              ? `<td rowspan='${vulnerabilityCount}' class='${
                  vul.isDirect ? 'is-direct' : 'is-indirect'
                }'>${REPORT_UTIL.buildPackage(vul, isBooleanFix)}</td>`
              : ''
          }

          <td>${REPORT_UTIL.buildVunerability(hasDepenciesList, via)}</td>
          
          <td class='text-center'>${REPORT_UTIL.buildSeverity(
            hasDepenciesList,
            vul,
            via
          )}</td>

          <td class='text-center'>${REPORT_UTIL.buildScore(via)}</td>

          <td>${REPORT_UTIL.getCWEValue(via.cwe)}</td>
            
          <td class='text-center'>
              ${via.url ? `<a href='${via.url}'>link</a>` : ''}
          </td>

        </tr>`;
      });

      if (vulArr.length > 0) {
        return vulArr.join('');
      }

      return '';
    }

    return `<tr>
          <td>
            <div>${vul.name}</div>
            <div>${vul.range}</div>
          </td>

          <td></td>
          <td></td>
          <td></td>
          <td></td>
          <td></td>
        </tr>`;
  },
  getVulnerabilitiesCount: (vul) => {
    if (vul.via instanceof Array) {
      return vul.via.length;
    }
    return 0;
  }
};

const runNPMAuditCommand = async (documentURI) => {
  const exec = util.promisify(require('child_process').exec);

  try {
    const result = await exec(
      'npm audit --json  --prefix ' +
        (process.platform !== 'win32' ? '/' : '') +
        dirname(documentURI.path.substring(1)),
      { windowsHide: true }
    );

    return { success: true, data: JSON.parse(result.stdout) };
  } catch (output) {
    if (output.stderr && output.stderr.length > 0) {
      return {
        success: false,
        data: output.stderr
      };
    }

    return {
      success: true,
      data: JSON.parse(output.stdout)
    };
  }
};

const renderAuditError = (error) => {
  const err = error || '';
  if (
    err.indexOf('Something went wrong, "npm WARN config global `--global`') > -1
  ) {
    webRenderer.renderError({
      actionHeader: REPORT_TITLE,
      hasSolution: `
      <div classs='box box-success'>
          <h3>Follow below steps to resolve the issue:</h3>

          <div class="mb-2">
              <div><b>Step 1:</b> Set Execution policy to make sure you can execute scripts:</div>
              <div class='i'>Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Force</div>
          </div>

          <div class="mb-2">  
              <div><b>Step 2:</b> Install npm-windows-upgrade package globally</div>
              <div class='i'>npm install --global --production npm-windows-upgrade</div>
          </div>

          <div class="mb-2">  
              <div><b>Step 3:</b> Upgrade npm to the latest version</div>
              <div class='i'>npm-windows-upgrade --npm-version latest</div>
          </div>

          <div class="mb-2">  
              <div><b>Step 4:</b> Revert the execution policy</div>
              <div class='i'>Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force</div>
          </div>
      </div>`,
      message: `<div class='mb-2'>Something went wrong, but this can be fixed.</div>`
    });
    return;
  }

  webRenderer.renderError({
    actionHeader: REPORT_TITLE,
    hasSolution: false,
    message: err
  });
};

const renderVulnerabilities = (vulnerabilitylist) => {
  if (vulnerabilitylist.length == 0) {
    return '';
  }

  let vulStr = `<div>
  <table class='table table-striped table-bordered table-sm'> 
    <tr>
      <th>Package</th>
      <th>Vulnerability</th>
      <th>Severity</th>
      <th title='${MSGS.SCORE_TOOLTIP}'>Score <sup>#</sup></th>
      <th>CWE <sup>@</sup></th>
      <th>GHSA <sup>$</sup></th>
    </tr>
  `;

  vulnerabilitylist.map((vul) => {
    vulStr += `${REPORT_UTIL.getVulnerabilitiesValue(vul)}`;
  });

  vulStr += `</table>
  </div>`;

  vulStr += `<div>
    <br/>
    <hr/> 
    <div><b>#</b>  <i>${MSGS.SCORE_TOOLTIP}</i></div>
    <div><b>@</b> <i>${MSGS.CWE_TOOLTIP}</i></div>
    <div><b>$</b>  <i>${MSGS.GHSA_TOOLTIP}</i></div>
    <div><div class='mb-1 mr-1 is-direct-indicator'>&nbsp;</div> The application is directly dependent/using the given package.</div>
    <div><div class='mr-1 is-indirect-indicator'>&nbsp;</div> The application is directly not using the given package, instead any of the direct dependency <div class='severity-box is-direct-indicator'>&nbsp;</div> is using the given package.</div>

  </div>`;

  return vulStr;
};

const createHTMLReport = async (data) => {
  let vulnerabilityList = [];
  if (Object.keys(data.vulnerabilities).length > 0) {
    vulnerabilityList = REPORT_UTIL.sortByDirect(
      Object.keys(data.vulnerabilities).map((key) => {
        return { ...data.vulnerabilities[key] };
      }),
      true
    );
  }

  const fixAvailableWithCompatibleUpdates = vulnerabilityList.filter((vul) => {
    return REPORT_UTIL.ifFixIsBoolean(vul.fixAvailable);
  }).length;

  const fixAvailablewithBreakingChanges = vulnerabilityList.filter((vul) => {
    return REPORT_UTIL.ifFixIsObject(vul.fixAvailable);
  }).length;

  const { critical, high, moderate, low, info } = data.metadata.vulnerabilities;
  const { dev, prod, optional, peer, peerOptional, total } =
    data.metadata.dependencies;

  const view = {
    commonCSS: COMMON_CSS,
    critical,
    high,
    moderate,
    low,
    info,
    dev,
    prod,
    optional,
    peer,
    peerOptional,
    totalDependencies: total,
    fixAvailableWithCompatibleUpdates,
    fixAvailablewithBreakingChanges
  };

  let content = render(await getTemplate(webRenderer.template), view);

  if (vulnerabilityList.length > 0) {
    content += renderVulnerabilities(vulnerabilityList);
  }

  webRenderer.renderContent(content);
};

const npmAuditCommand = async (context) => {
  await webRenderer.init(context);
  webRenderer.renderLoader();

  const packageLockFile = await findFile('package-lock.json');

  if (!packageLockFile) {
    renderAuditError(MSGS.PACKAGE_LOCK_JSON_NOT_FOUND);
    return;
  }

  window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: `Running ${REPORT_TITLE} ...`,
      cancellable: false
    },
    async () => {
      const result = await runNPMAuditCommand(packageLockFile.uri);

      if (result) {
        if (!result.success) {
          renderAuditError(JSON.stringify(result.data));
          return;
        }

        // const folderUri = vscode.workspace.workspaceFolders[0].uri;
        // const reportFileName = posix.join(
        //   folderUri.path,
        //   `${REPORT_FOLDER_NAME}/result.json`
        // );

        // const fileUri = folderUri.with({ path: `${reportFileName}` });

        // await vscode.workspace.fs.writeFile(
        //   fileUri,
        //   Buffer.from(JSON.stringify(result.data), 'utf8')
        // );

        createHTMLReport(result.data);
      }
    }
  );
};

module.exports = { npmAuditCommand };