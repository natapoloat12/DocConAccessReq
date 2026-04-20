let userEmail = '';

// Simple regex patterns
const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateIp(ip) {
    return ipRegex.test(ip);
}

function validateEmail(email) {
    return emailRegex.test(email);
}

document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('requestForm');
    const submitBtn = document.getElementById('submitBtn');
    const statusMessage = document.getElementById('statusMessage');
    const statusIcon = document.getElementById('statusIcon');
    const statusText = document.getElementById('statusText');
    const ccEmailsInput = document.getElementById('cc_emails');
    const loadingScreen = document.getElementById('loadingScreen');
    const mainContainer = document.getElementById('mainContainer');
    const entriesContainer = document.getElementById('entriesContainer');
    const addEntryBtn = document.getElementById('addEntryBtn');
    const docsContainer = document.getElementById('docsContainer');
    const addDocBtn = document.getElementById('addDocBtn');
    const logoutBtn = document.getElementById('logoutBtn');

    function showStatus(message, isError = false) {
        if (!statusMessage || !statusIcon || !statusText) return;
        
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
        row.className = 'entry-row flex flex-col sm:flex-row gap-3 items-end sm:items-center group transition-all relative';
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
            <button type="button" class="remove-row p-2.5 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-all" aria-label="Remove Row">
                <i class="fas fa-trash-alt"></i>
            </button>
        `;
        return row;
    }

    function createDocRow() {
        const row = document.createElement('div');
        row.className = 'doc-row flex gap-3 items-center group transition-all relative';
        row.innerHTML = `
            <div class="flex-1">
                <label class="block text-[10px] uppercase font-bold text-gray-400 mb-1 ml-1">ชื่อเอกสาร (Document Name)</label>
                <div class="relative">
                    <span class="absolute inset-y-0 left-0 pl-3 flex items-center text-gray-400">
                        <i class="fas fa-file-alt text-xs"></i>
                    </span>
                    <input type="text" name="doc_name" placeholder="ระบุชื่อเอกสาร เช่น Document1" required
                        class="block w-full pl-9 pr-3 py-2.5 bg-white border border-gray-300 rounded-lg text-sm transition-all focus:ring-2 focus:ring-orange-500/20 focus:border-orange-500 focus:outline-none">
                </div>
            </div>
            <button type="button" class="remove-doc-row p-2.5 mt-5 text-gray-400 hover:text-red-500 hover:bg-red-50 rounded-lg transition-all" aria-label="Remove Document">
                <i class="fas fa-trash-alt"></i>
            </button>
        `;
        return row;
    }

    // Initial Rows - ensure exactly 1 row is added if empty
    if (entriesContainer && entriesContainer.children.length === 0) {
        entriesContainer.appendChild(createEntryRow());
    }

    if (docsContainer && docsContainer.children.length === 0) {
        docsContainer.appendChild(createDocRow());
    }

    if (addEntryBtn && entriesContainer) {
        addEntryBtn.addEventListener('click', () => {
            const newRow = createEntryRow();
            entriesContainer.appendChild(newRow);
            newRow.classList.add('animate-fadeIn');
            const firstInput = newRow.querySelector('input');
            if (firstInput) firstInput.focus();
        });
    }

    if (addDocBtn && docsContainer) {
        addDocBtn.addEventListener('click', () => {
            const newRow = createDocRow();
            docsContainer.appendChild(newRow);
            newRow.classList.add('animate-fadeIn');
            const docInput = newRow.querySelector('input');
            if (docInput) docInput.focus();
        });
    }

    // Event delegation for removal
    if (entriesContainer) {
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
    }

    if (docsContainer) {
        docsContainer.addEventListener('click', (e) => {
            const removeBtn = e.target.closest('.remove-doc-row');
            if (removeBtn) {
                const row = removeBtn.closest('.doc-row');
                if (document.querySelectorAll('.doc-row').length > 1) {
                    row.style.opacity = '0';
                    row.style.transform = 'translateX(20px)';
                    setTimeout(() => row.remove(), 200);
                } else {
                    alert("ต้องมีอย่างน้อย 1 รายการ");
                }
            }
        });
    }

    // --- Auth & Submission ---

    async function checkAuth() {
        try {
            const response = await fetch('/api/verify', {
                method: 'GET',
                headers: {
                    'Cache-Control': 'no-cache, no-store, must-revalidate',
                    'Pragma': 'no-cache',
                    'Expires': '0'
                },
                cache: 'no-store'
            });
            
            if (!response.ok) {
                window.location.replace('/login.html');
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
            if (user.email) {
                userEmail = user.email;
            }
        } catch (err) {
            console.error('Connection error:', err);
            window.location.replace('/login.html');
        }
    }

    checkAuth();

    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            // Collect, trim, filter, and deduplicate document names
            const docRows = document.querySelectorAll('.doc-row input[name="doc_name"]');
            const docNames = Array.from(docRows)
                .map(input => input.value.trim())
                .filter(val => val !== "");
            
            const uniqueDocNames = [...new Set(docNames)];

            if (uniqueDocNames.length === 0) {
                showStatus("กรุณาระบุชื่อเอกสารอย่างน้อย 1 รายการ", true);
                return;
            }
            
            const document_name = uniqueDocNames.join(',');

            const ccEmailsValue = ccEmailsInput ? ccEmailsInput.value.trim() : '';
            const dateVal = document.getElementById('expiry') ? document.getElementById('expiry').value : '';
            const expiry = dateVal ? `${dateVal}T23:59` : '';

            // Parse and validate CC emails
            let cc_emails = [];
            if (ccEmailsValue) {
                cc_emails = ccEmailsValue.split(',').map(email => email.trim()).filter(email => email !== "");
                for (const email of cc_emails) {
                    if (!validateEmail(email)) {
                        showStatus(`รูปแบบอีเมลไม่ถูกต้อง: ${email}`, true);
                        if (ccEmailsInput) ccEmailsInput.classList.add('border-red-500');
                        return;
                    }
                }
            }
            if (ccEmailsInput) ccEmailsInput.classList.remove('border-red-500');

            const entries = [];
            const rows = document.querySelectorAll('.entry-row');
            const seenIps = new Set();
            let isValid = true;

            rows.forEach(row => {
                const nameInput = row.querySelector('input[name="name"]');
                const ipInput = row.querySelector('input[name="ip"]');
                const name = nameInput ? nameInput.value.trim() : '';
                const ip = ipInput ? ipInput.value.trim() : '';

                if (nameInput) nameInput.classList.remove('border-red-500');
                if (ipInput) ipInput.classList.remove('border-red-500');

                if (!validateIp(ip)) {
                    if (ipInput) ipInput.classList.add('border-red-500');
                    isValid = false;
                } else if (seenIps.has(ip)) {
                    alert(`IP ซ้ำกัน: ${ip}`);
                    if (ipInput) ipInput.classList.add('border-red-500');
                    isValid = false;
                } else if (name === "") {
                    if (nameInput) nameInput.classList.add('border-red-500');
                    isValid = false;
                } else {
                    seenIps.add(ip);
                    entries.push({ name, ip });
                }
            });

            if (!isValid || entries.length === 0) {
                showStatus("กรุณาตรวจสอบความถูกต้องของข้อมูล", true);
                return;
            }

            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.dataset.originalContent = submitBtn.innerHTML;
                submitBtn.innerHTML = '<i class="fas fa-circle-notch animate-spin mr-2"></i> กำลังส่งคำขอ...';
            }
            if (statusMessage) statusMessage.classList.add('hidden');

            try {
                const response = await fetch('/api/firewall/request', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        entries, 
                        confirmation_email: userEmail || null, 
                        cc_emails,
                        expiry, 
                        document_name 
                    }),
                });

                if (response.status === 401) {
                    window.location.href = '/login.html';
                    return;
                }

                const data = await response.json();
                if (response.ok) {
                    showStatus(data.message || 'ส่งคำขอสำเร็จแล้ว!');
                    
                    // Reset to one row for entries
                    if (entriesContainer) {
                        entriesContainer.innerHTML = '';
                        entriesContainer.appendChild(createEntryRow());
                    }
                    
                    // Reset to one row for documents
                    if (docsContainer) {
                        docsContainer.innerHTML = '';
                        docsContainer.appendChild(createDocRow());
                    }

                    form.reset();
                    checkAuth();
                } else {
                    showStatus(data.message || 'เกิดข้อผิดพลาดในการส่งคำขอ', true);
                }
            } catch (err) {
                console.error(err);
                showStatus('ไม่สามารถเชื่อมต่อกับเซิร์ฟเวอร์ได้', true);
            } finally {
                if (submitBtn) {
                    submitBtn.disabled = false;
                    if (submitBtn.dataset.originalContent) {
                        submitBtn.innerHTML = submitBtn.dataset.originalContent;
                    }
                }
            }
        });
    }

    // Logout
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            try {
                await fetch('/api/logout', { method: 'POST' });
            } catch (err) {
                console.error("Logout error", err);
            } finally {
                window.location.href = '/login.html';
            }
        });
    }

    // --- Inactivity Timeout ---
    let inactivityTimer;
    const INACTIVITY_LIMIT_MS = 5 * 60 * 1000; // 5 minutes

    async function logoutDueToInactivity() {
        try {
            await fetch('/api/logout', { method: 'POST' });
        } catch (e) {
            console.error("Auto-logout due to inactivity failed", e);
        } finally {
            alert("Your session has expired due to 5 minutes of inactivity. Please log in again.");
            window.location.href = '/login.html';
        }
    }

    function resetInactivityTimer() {
        clearTimeout(inactivityTimer);
        inactivityTimer = setTimeout(logoutDueToInactivity, INACTIVITY_LIMIT_MS);
    }

    // Listen for common user interactions to reset the timer
    ['mousemove', 'keydown', 'mousedown', 'scroll', 'touchstart'].forEach(event => {
        document.addEventListener(event, resetInactivityTimer, { passive: true });
    });

    // Initialize the timer on page load
    resetInactivityTimer();
});