const vscode = require('vscode');
const { COMMANDS } = require('./constants');
const { npmAuditCommand } = require('./npm-audit');
const { registerCommand } = require('./util');

/**
 * @param {vscode.ExtensionContext} context
 */
function activate(context) {
  console.log(
    'Congratulations, your extension "npm-audit-ui-geeks" is now active!'
  );

  const npmAuditCmd = registerCommand(COMMANDS.NPM_AUDIT, () =>
    npmAuditCommand(context)
  );
  context.subscriptions.push(npmAuditCmd);
}

function deactivate() {}

module.exports = {
  activate,
  deactivate
};
