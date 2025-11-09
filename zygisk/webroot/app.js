import { exec } from 'kernelsu';

const MODULE_ROOT = '/data/adb/modules/drizzle-zygisk';
const CONFIG_DIR = `${MODULE_ROOT}/config`;
const PACKAGE_LIST = `${CONFIG_DIR}/package_custom.list`;
const TARGETS_JSON = `${CONFIG_DIR}/targets.json`;
const MCP_BIND_FILE = `${CONFIG_DIR}/mcp_bind`;
const PID_FILE = `${MODULE_ROOT}/run/mcp-server.pid`;
const MCP_LOG_DIR = `${MODULE_ROOT}/run`;

const listContainer = document.getElementById('package-list');
const searchInput = document.getElementById('search');
const summaryText = document.getElementById('summary-text');
const mcpBindInput = document.getElementById('mcp-bind');
const statusPanel = document.getElementById('status');
const manualPackageInput = document.getElementById('manual-package');

let allPackages = [];
let selectedPackages = new Set();
let searchTerm = '';

function shellEscape(str) {
  return str.replace(/'/g, `'\"'\"'`);
}

function encodeBase64(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

async function writeFile(path, content) {
  const encoded = encodeBase64(content);
  await exec(`sh -c "echo '${encoded}' | base64 -d > ${path}"`);
}

async function readFile(path) {
  const { stdout } = await exec(`sh -c "if [ -f ${path} ]; then cat ${path}; fi"`);
  return stdout ?? '';
}

function showStatus(message, kind = 'info') {
  statusPanel.classList.remove('success', 'error');
  if (kind === 'success') {
    statusPanel.classList.add('success');
  } else if (kind === 'error') {
    statusPanel.classList.add('error');
  }
  const now = new Date().toLocaleTimeString();
  statusPanel.textContent = `[${now}] ${message}`;
}

function updateSummary() {
  summaryText.textContent = `已选择 ${selectedPackages.size} / ${allPackages.length} 个应用`;
}

function filterPackages() {
  if (!searchTerm) {
    return allPackages;
  }
  return allPackages.filter((pkg) => pkg.toLowerCase().includes(searchTerm));
}

function renderPackages() {
  const filtered = filterPackages();
  listContainer.innerHTML = filtered
    .map(
      (pkg) => `
        <label class="package-item">
          <input type="checkbox" data-package="${pkg}" ${selectedPackages.has(pkg) ? 'checked' : ''}/>
          <span>${pkg}</span>
        </label>
      `
    )
    .join('');
  updateSummary();
}

async function loadPackages() {
  const { stdout } = await exec('pm list packages -3');
  allPackages = stdout
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.startsWith('package:'))
    .map((line) => line.replace('package:', ''))
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b));
}

async function loadSelectedPackages() {
  const custom = await readFile(PACKAGE_LIST);
  let lines = custom
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
  if (lines.length === 0) {
    try {
      const { stdout } = await exec(`cat ${TARGETS_JSON}`);
      const json = JSON.parse(stdout);
      if (Array.isArray(json.packages)) {
        lines = json.packages;
      }
    } catch (err) {
      console.warn('Failed to parse targets.json', err);
    }
  }
  selectedPackages = new Set(lines);
}

async function loadMcpBind() {
  const bind = (await readFile(MCP_BIND_FILE)).trim();
  mcpBindInput.value = bind || '0.0.0.0:45831';
}

async function saveSelection() {
  const ordered = Array.from(selectedPackages).sort().join('\n');
  await writeFile(PACKAGE_LIST, `${ordered}\n`);
  showStatus('包名列表已保存', 'success');
}

async function saveMcpBind() {
  const bind = mcpBindInput.value.trim() || '0.0.0.0:45831';
  await writeFile(MCP_BIND_FILE, `${bind}\n`);
  return bind;
}

async function restartMcp(bind) {
  const script = `
    if [ -f ${PID_FILE} ]; then
      kill $(cat ${PID_FILE}) 2>/dev/null || true;
      rm ${PID_FILE};
    fi;
    mkdir -p ${MCP_LOG_DIR};
    ${MODULE_ROOT}/bin/drizzle_dumper mcp-server --bind ${bind} >/dev/null 2>&1 &
    echo $! > ${PID_FILE}
  `.trim();
  await exec(`sh -c '${shellEscape(script)}'`);
  showStatus(`MCP 服务已重启 (${bind})`, 'success');
}

async function triggerDump(pkg) {
  const safe = /^[\w\.\-]+$/.test(pkg);
  if (!safe) {
    showStatus('包名包含非法字符', 'error');
    return;
  }
  const logFile = `${MCP_LOG_DIR}/dump_${Date.now()}.log`;
  const cmd = `${MODULE_ROOT}/bin/drizzle_dumper dump ${pkg} --zygisk >${logFile} 2>&1 &`;
  await exec(`sh -c '${shellEscape(cmd)}'`);
  showStatus(`已后台执行 dump，日志: ${logFile}`, 'success');
}

function attachEventListeners() {
  listContainer.addEventListener('change', (event) => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement) || !target.dataset.package) {
      return;
    }
    const pkg = target.dataset.package;
    if (target.checked) {
      selectedPackages.add(pkg);
    } else {
      selectedPackages.delete(pkg);
    }
    updateSummary();
  });

  searchInput.addEventListener('input', (event) => {
    searchTerm = event.target.value.trim().toLowerCase();
    renderPackages();
  });

  document.getElementById('refresh').addEventListener('click', async () => {
    try {
      showStatus('正在刷新包名…');
      await loadPackages();
      renderPackages();
      showStatus('包名列表已刷新', 'success');
    } catch (err) {
      console.error(err);
      showStatus(`刷新失败: ${err}`, 'error');
    }
  });

  document.getElementById('select-all').addEventListener('click', () => {
    filterPackages().forEach((pkg) => selectedPackages.add(pkg));
    renderPackages();
  });

  document.getElementById('select-none').addEventListener('click', () => {
    filterPackages().forEach((pkg) => selectedPackages.delete(pkg));
    renderPackages();
  });

  document.getElementById('invert-selection').addEventListener('click', () => {
    filterPackages().forEach((pkg) => {
      if (selectedPackages.has(pkg)) {
        selectedPackages.delete(pkg);
      } else {
        selectedPackages.add(pkg);
      }
    });
    renderPackages();
  });

  document.getElementById('save-config').addEventListener('click', async () => {
    try {
      showStatus('保存中…');
      await saveSelection();
      const bind = await saveMcpBind();
      await restartMcp(bind.trim());
    } catch (err) {
      console.error(err);
      showStatus(`保存失败: ${err}`, 'error');
    }
  });

  document.getElementById('restart-mcp').addEventListener('click', async () => {
    try {
      const bind = await saveMcpBind();
      await restartMcp(bind.trim());
    } catch (err) {
      console.error(err);
      showStatus(`重启失败: ${err}`, 'error');
    }
  });

  document.getElementById('trigger-dump').addEventListener('click', async () => {
    const pkg = manualPackageInput.value.trim();
    if (!pkg) {
      showStatus('请先输入包名', 'error');
      return;
    }
    try {
      await triggerDump(pkg);
    } catch (err) {
      console.error(err);
      showStatus(`触发失败: ${err}`, 'error');
    }
  });
}

async function init() {
  try {
    showStatus('初始化…');
    await loadPackages();
    await loadSelectedPackages();
    await loadMcpBind();
    renderPackages();
    attachEventListeners();
    showStatus('初始化完成', 'success');
  } catch (err) {
    console.error(err);
    showStatus(`初始化失败: ${err}`, 'error');
  }
}

init();
