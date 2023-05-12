const { MSGS } = require('./constants');
const { window, workspace, commands } = require('vscode');

const logMsg = (msg, inModal) => {
  window.showInformationMessage(msg, { modal: inModal || false });
};

const logErrorMsg = (msg, inModal) => {
  window.showErrorMessage(msg, { modal: inModal || false });
};

const findFile = (fileName) => {
  return new Promise((resolve, reject) => {
    workspace.findFiles(`**/${fileName}`).then(
      async (resp) => {
        if (resp) {
          resp = resp.filter((r) => r.path.indexOf('node_modules') === -1);
          if (resp.length === 1) {
            return resolve(await workspace.openTextDocument(resp[0].path));
          }

          const selectedFile = await window.showQuickPick(
            resp.map((r) => r.path)
          );

          if (selectedFile) {
            return resolve(await workspace.openTextDocument(selectedFile));
          }

          return reject(MSGS.INVALID_SELECTION);
        }

        resolve(null);
      },
      () => {
        reject('File Not Found');
      }
    );
  });
};

const getFileContent = async (file) => {
  if (!file) {
    return '';
  }

  return await file.getText();
};

const openFile = async (fileUri) => {
  const doc = await workspace.openTextDocument(fileUri);
  await window.showTextDocument(doc, { preview: false });
};

const registerCommand = (command, handlerMethod) => {
  return commands.registerCommand(command, async () => {
    await handlerMethod();
  });
};

const isDarkTheme = () => {
  return window.activeColorTheme.kind === 2;
};

const sortByKey = (list, key, desc) => {
  if (!list || !key) {
    return list;
  }

  if (desc) {
    return list.sort((a, b) =>
      a[key] < b[key] ? 1 : b[key] < a[key] ? -1 : 0
    );
  }

  return list.sort((a, b) => (a[key] > b[key] ? 1 : b[key] > a[key] ? -1 : 0));
};

const convertObjectToArray = (obj, keyAttribute, valueAttribute) => {
  if (!obj || Object.keys(obj).length === 0) {
    return [];
  }

  return Object.keys(obj).map((key) => {
    return { [keyAttribute]: key, [valueAttribute]: obj[key] };
  });
};

const severityTag = (severity) => {
  if (!severity) {
    return '';
  }

  severity = severity || '';
  const severityText = severity.charAt(0).toUpperCase() + severity.slice(1);
  return `<div class='severity-box severity-${severity}'>${severityText}</div>`;
};

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
      ? `<div>${sev}Depends on vulnerable versions of <b><a href="#${via}" class='internal-link'>${via}</a></b>${rightSection}</div>`
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
      vulArr = vul.via.map((via, index) => {
        const hasDepenciesList = REPORT_UTIL.isString(via);
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
        returnText += `<div class='mt-1'>Depends on vulnerable versions of `;
        dependentVul.map((v, indx) => {
          returnText += `${
            indx > 0 ? ', ' : ''
          }<b><a href='#${v}' class='internal-link'>${v}</a></b>`;
        });
        returnText += `</div>`;
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

module.exports = {
  logMsg,
  logErrorMsg,
  findFile,
  getFileContent,
  openFile,
  registerCommand,
  convertObjectToArray,
  sortByKey,
  severityTag,
  isDarkTheme,
  REPORT_UTIL
};
