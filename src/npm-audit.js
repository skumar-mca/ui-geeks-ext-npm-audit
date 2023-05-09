const { render } = require('mustache');
const { dirname } = require('path');
const util = require('util');
const { window } = require('vscode');
const vscode = require('vscode');
const { findFile, sortByKey, getFileContent, severityTag } = require('./util');
const {
  MSGS,
  COMMON_CSS,
  REPORT_TEMPLATE,
  REPORT_TITLE,
  COLORS
} = require('./constants');
const { WebRenderer, getTemplate } = require('./web-renderer');

const webRenderer = new WebRenderer(REPORT_TEMPLATE, REPORT_TITLE);

const REPORT_UTIL = {
  isObject: (obj) => {
    return typeof obj === 'object';
  },
  isString: (txt) => {
    return typeof txt === 'string';
  },
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
        ? `<div class="fix-green b mt-1">fix available via 'npm audit fix'</div>`
        : `<div class="fix-red b mt-1">No fix available</div>`
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
  buildVunerability: (vul, hasDepenciesList, via) => {
    const rightSection = `<div class='vul-detail-right'>
            <div>${REPORT_UTIL.buildScore(via)}</div>
            <div>${REPORT_UTIL.getCWEValue(via.cwe)}</div>
            ${
              via.url
                ? `<div class='bdg-sm'><a href='${via.url}'>${via.url.replace(
                    'https://github.com/advisories/',
                    ''
                  )}</a></div>`
                : ''
            }
          </div>`;

    const sev = `<span class='mr-1'>${REPORT_UTIL.buildSeverity(
      hasDepenciesList,
      vul,
      via
    )}</span>`;

    return hasDepenciesList
      ? `<div>${sev}Depends on vulnerable versions of <b>${via}</b>${rightSection}</div>`
      : `<b>${sev} ${via.title}</b>${
          via.range
            ? `<br/><div class='mt-1'><span class='impacted'>Impacted Versions: <b>${via.range}</b></span>${rightSection}</div>`
            : `${rightSection}`
        }`;
  },
  buildSeverity: (hasDepenciesList, vul, via) => {
    return severityTag(hasDepenciesList ? vul.severity : via.severity);
  },
  buildScore: (via) => {
    return via.cvss && via.cvss.score
      ? `<div class='bdg-sm'>Score: <span><b>${via.cvss.score}</b>/10</span></div>`
      : '';
  },
  buildPackage: (vul, isBooleanFix) => {
    return `<div>
              ${REPORT_UTIL.buildPackageName(vul)}
              <span class='color-grey'><i>v${vul.range}</i></span>
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
        return `<a href='https://cwe.mitre.org/data/definitions/${cweVal}.html'>CWE-${cweVal}</a>`;
      });

      if (cweArr.length > 0) {
        return `<div class='bdg-sm'>${cweArr.join(' | ')}</div>`;
      }

      return '';
    }
    return '';
  },
  getVulnerabilitiesValue: (vul) => {
    let vulArr = [];
    if (vul.via instanceof Array) {
      const hasDepenciesList =
        REPORT_UTIL.ifViaIsArrayOfString(vul.via) ||
        REPORT_UTIL.isString(vul.via);

      vulArr = vul.via.map((via, index) => {
        return `<li class='li-vul'>
          <div>${REPORT_UTIL.buildVunerability(
            vul,
            hasDepenciesList,
            via
          )}</div>
          
        </li>`;
      });

      if (vulArr.length > 0) {
        return vulArr.join('');
      }

      return '';
    }
  },
  getVulnerabilitiesText: (vul) => {
    if (vul.via instanceof Array) {
      let directVul = [];
      let dependentVul = [];
      let returnText = ``;
      let vulText = ``;
      vul.via.map((via) => {
        if (REPORT_UTIL.isObject(via) && directVul.indexOf(via.title) === -1) {
          directVul.push(via.title);
          vulText += `<div><a class='no-link' href='${via.url}'><b>${via.title}</b></a>.</div>`;
        }

        if (REPORT_UTIL.isString(via) && dependentVul.indexOf(via) === -1) {
          dependentVul.push(via);
        }
      });

      if (directVul.length > 0) {
        returnText += ``;
        returnText += vulText;
        returnText += ``;
      }

      if (dependentVul.length > 0) {
        returnText += `<div class='mt-1'>Depends on vulnerable versions of <b>${dependentVul.join(
          ', '
        )}</b></div>`;
      }

      return returnText;
    }

    return '';
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

const renderVulnerabilitiesSummary = (vulnerabilitylist) => {
  if (vulnerabilitylist.length == 0) {
    return '';
  }

  let vulStr = `<div>
  <h3>Vulnerability Report Summary</h3>

  <table class='table table-striped table-bordered table-sm'> 
    <tr>
      <th class='text-left'>Package</th>
      <th>Severity</th>
      <th>Vulnerability</th>
      <th>Fix Available</th>
    </tr>
  `;

  vulnerabilitylist.map((vul) => {
    const isBooleanFix = REPORT_UTIL.ifFixIsBoolean(vul.fixAvailable);

    vulStr += `
    <tr>
      <td>
        <b><a href='#${vul.name}' class='no-link'>${vul.name}</a></b>
      </td>
      <td class='text-center'>${severityTag(vul.severity)}</td>
      <td>${REPORT_UTIL.getVulnerabilitiesText(vul)}</td>
      <td class='td-fix-avl'>${
        isBooleanFix
          ? vul.fixAvailable === true
            ? `<div class='fix-green b'>Yes</div>`
            : `<div class='fix-red b'>No</div>`
          : `<div class='fix-yellow b'>Breaking</div>`
      }</td>
    </tr>`;
  });

  vulStr += `</table>
  </div>`;

  return vulStr;
};

const renderVulnerabilities = (vulnerabilitylist) => {
  if (vulnerabilitylist.length == 0) {
    return '';
  }

  let vulStr = `<div>
    <h3>Vulnerability Report Details</h3>`;

  vulnerabilitylist.map((vul) => {
    const isBooleanFix = REPORT_UTIL.ifFixIsBoolean(vul.fixAvailable);
    vulStr += `
    <div  id='${vul.name}' class='package-vul-box box bl-${vul.severity}'>
      <div>
          ${REPORT_UTIL.buildPackage(vul, isBooleanFix)}
      </div>

      <div>
        <h3>Vulnerabilities</h3>
        <ul>
          ${REPORT_UTIL.getVulnerabilitiesValue(vul)}
        </ul>
      </div>
    </div>`;
  });

  vulStr += `</div>`;

  vulStr += `<div>
    <br/>
    <hr/> 
    <div><b># Score: </b>  <i>${MSGS.SCORE_TOOLTIP}</i></div>
    <div><b># CWE: </b> <i>${MSGS.CWE_TOOLTIP}</i></div>
    <div><b># GHSA: </b>  <i>${MSGS.GHSA_TOOLTIP}</i></div>
    <br/><br/>
  </div>`;

  return vulStr;
};

const getApplicationMeta = async () => {
  const packageFile = await findFile('package.json');
  if (!packageFile) {
    return null;
  }

  const fileContent = await getFileContent(packageFile);
  if (!fileContent) {
    return {
      success: false,
      data: 'Error: Reading content of package.json'
    };
  }

  const packageJSON = JSON.parse(fileContent);

  const {
    name,
    version,
    description,
    devDependencies,
    dependencies,
    peerDependencies
  } = packageJSON;

  return {
    appName: name,
    appVersion: version,
    appDescription: description,
    appTotalDep: devDependencies
      ? Object.keys(devDependencies).length
      : 0 + dependencies
      ? Object.keys(dependencies).length
      : 0 + peerDependencies
      ? Object.keys(peerDependencies).length
      : 0
  };
};

const createHTMLReport = async (data) => {
  let vulnerabilityList = [];
  if (Object.keys(data.vulnerabilities).length > 0) {
    vulnerabilityList = REPORT_UTIL.sortBySeverity(
      Object.keys(data.vulnerabilities).map((key) => {
        return { ...data.vulnerabilities[key] };
      })
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

  let view = {
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
    fixAvailablewithBreakingChanges,
    totalVulnerabilities: critical + high + moderate + low + info,
    depChartDataList: [dev, prod, optional, peer, peerOptional],
    depChartColorsList: [
      COLORS.moderate,
      COLORS.info,
      COLORS.low,
      COLORS.high,
      COLORS.grey
    ],
    vulChartDataList: [critical, high, moderate, low, info],
    chartColorsList: [
      COLORS.critical,
      COLORS.high,
      COLORS.moderate,
      COLORS.low,
      COLORS.info
    ]
  };

  const applicationMeta = await getApplicationMeta();
  if (applicationMeta) {
    const { appName, appVersion, appDescription, appTotalDep } =
      applicationMeta;
    view = { ...view, appName, appVersion, appDescription, appTotalDep };
  }

  let content = render(await getTemplate(webRenderer.template), view);

  if (vulnerabilityList.length > 0) {
    content += renderVulnerabilitiesSummary(vulnerabilityList);
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

        createHTMLReport(result.data);
      }
    }
  );
};

module.exports = { npmAuditCommand };
