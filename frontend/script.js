const form = document.getElementById('requestForm');
const submitBtn = document.getElementById('submitBtn');
const statusMessage = document.getElementById('statusMessage');
const statusIcon = document.getElementById('statusIcon');
const statusText = document.getElementById('statusText');
const emailInput = document.getElementById('email');
const loadingScreen = document.getElementById('loadingScreen');
const mainContainer = document.getElementById('mainContainer');
const entriesContainer = document.getElementById('entriesContainer');
const addEntryBtn = document.getElementById('addEntryBtn');

// Simple regex patterns
const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateIp(ip) {
    return ipRegex.test(ip);
}

function validateEmail(email) {
    return emailRegex.test(email);
}

function showStatus(message, isError = false) {
    statusMessage.classList.remove('hidden', 'bg-red-50', 'text-red-700', 'border-red-100', 'bg-green-50', 'text-green-700', 'border-green-100');
    
    if (isError) {
        statusMessage.classList.add('bg-red-50', 'text-red-700', 'border-red-100');
        statusIcon.innerHTML = '<i class="fas fa-exclamation-triangle text-red-400"></i>';
    } else {
        statusMessage.classList.add('bg-green-50', 'text-green-700', 'border-green-100');
        statusIcon.innerHTML = '<i class="fas fa-check-circle text-green-400"></i>';
    }
    
    statusText.textContent = message;
    statusMessage.classList.remove('hidden');
    
    // Scroll to status
    statusMessage.scrollIntoView({ behavior: 'smooth', block: 'center' });
}

// --- Dynamic Row Management ---

function createEntryRow() {
    const row = document.createElement('div');
    row.className = 'entry-row flex flex-col sm:flex-row gap-3 items-end sm:items-center group bg-gray-50 p-4 rounded-xl border border-gray-200 transition-all hover:border-orange-200';
    row.innerHTML = `
        <div class="w-full sm:flex-1">
            <label class="block text-[10px] uppercase font-bold text-gray-400 mb-1 ml-1">ชื่อ (Name)</label>
            <div class="relative">
                <span class="absolute inset-y-0 left-0 pl-3 flex items-center text-gray-400">
                    <i class="fas fa-tag text-xs"></i>
                </span>
                <input type="text" name="name" placeholder="เช่น Natapol Tirakhan" required
                    class="block w-full pl-9 pr-3 py-2.5 bg-white border border-gray-300 rounded-lg text-sm transition-all focus:ring-2 focus:ring-orange-500/20 focus:border-orange-500 focus:outline-none">
            </div>
        </div>
        <div class="w-full sm:flex-1">
            <label class="block text-[10px] uppercase font-bold text-gray-400 mb-1 ml-1">IP Address</label>
            <div class="relative">
                <span class="absolute inset-y-0 left-0 pl-3 flex items-center text-gray-400">
                    <i class="fas fa-network-wired text-xs"></i>
                </span>
                <input type="text" name="ip" placeholder="เช่น 10.10.214.251" required
                    class="ip-input block w-full pl-9 pr-3 py-2.5 bg-white border border-gray-300 rounded-lg text-sm transition-all focus:ring-2 focus:ring-orange-500/20 focus:border-orange-500 focus:outline-none">
            </div>
        </div>
        <button type="button" class="remove-row p-2.5 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-all">
            <i class="fas fa-trash-alt"></i>
        </button>
    `;

    return row;
}

// Initial Row
entriesContainer.appendChild(createEntryRow());

addEntryBtn.addEventListener('click', () => {
    const newRow = createEntryRow();
    entriesContainer.appendChild(newRow);
    newRow.classList.add('animate-fadeIn');
});

// Event delegation for removal
entriesContainer.addEventListener('click', (e) => {
    const removeBtn = e.target.closest('.remove-row');
    if (removeBtn) {
        const row = removeBtn.closest('.entry-row');
        if (document.querySelectorAll('.entry-row').length > 1) {
            row.style.opacity = '0';
            row.style.transform = 'translateX(20px)';
            setTimeout(() => row.remove(), 200);
        } else {
            alert("ต้องมีอย่างน้อย 1 รายการ");
        }
    }
});

// --- Auth & Submission ---

async function checkAuth() {
    try {
        const response = await fetch('/api/verify');
        if (!response.ok) {
            window.location.href = '/login.html';
            return;
        }
        const user = await response.json();
        if (loadingScreen) {
            loadingScreen.style.opacity = '0';
            setTimeout(() => loadingScreen.style.display = 'none', 300);
        }
        if (mainContainer) {
            mainContainer.style.display = 'block';
        }
        if (user.email && emailInput) {
            emailInput.value = user.email;
        }
    } catch (err) {
        console.error('Connection error:', err);
    }
}

checkAuth();

form.addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const documentNameInput = document.getElementById('document_name');
    const document_name = documentNameInput ? documentNameInput.value.trim() : '';
    const email = emailInput.value.trim();
    const dateVal = document.getElementById('expiry').value;
    const expiry = dateVal ? `${dateVal}T23:59` : '';

    const entries = [];
    const rows = document.querySelectorAll('.entry-row');
    const seenIps = new Set();
    let isValid = true;

    if (!document_name) {
        showStatus("กรุณาระบุชื่อเอกสาร", true);
        return;
    }

    rows.forEach(row => {
        const nameInput = row.querySelector('input[name="name"]');
        const ipInput = row.querySelector('input[name="ip"]');
        const name = nameInput.value.trim();
        const ip = ipInput.value.trim();

        nameInput.classList.remove('border-red-500');
        ipInput.classList.remove('border-red-500');

        if (!validateIp(ip)) {
            ipInput.classList.add('border-red-500');
            isValid = false;
        } else if (seenIps.has(ip)) {
            alert(`IP ซ้ำกัน: ${ip}`);
            ipInput.classList.add('border-red-500');
            isValid = false;
        } else {
            seenIps.add(ip);
            entries.push({ name, ip });
        }
    });

    if (!isValid) {
        showStatus("กรุณาตรวจสอบความถูกต้องของข้อมูล", true);
        return;
    }

    submitBtn.disabled = true;
    const originalBtnContent = submitBtn.innerHTML;
    submitBtn.innerHTML = '<i class="fas fa-circle-notch animate-spin mr-2"></i> กำลังส่งคำขอ...';
    statusMessage.classList.add('hidden');

    try {
        const response = await fetch('/api/firewall/request', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ entries, email: email || null, expiry, document_name }),
        });

        if (response.status === 401) {
            window.location.href = '/login.html';
            return;
        }

        const data = await response.json();
        if (response.ok) {
            showStatus(data.message || 'ส่งคำขอสำเร็จแล้ว!');
            // Reset to one row
            entriesContainer.innerHTML = '';
            entriesContainer.appendChild(createEntryRow());
            form.reset();
            checkAuth();
        } else {
            showStatus(data.message || 'เกิดข้อผิดพลาดในการส่งคำขอ', true);
        }
    } catch (err) {
        showStatus('ไม่สามารถเชื่อมต่อกับเซิร์ฟเวอร์ได้', true);
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalBtnContent;
    }
});

// Logout
const logoutBtn = document.getElementById('logoutBtn');
if (logoutBtn) {
    logoutBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = '/login.html';
    });
}
