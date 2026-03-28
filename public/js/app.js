document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('corp_token');
    const path = window.location.pathname;

    // --- Login Page Logic ---
    const loginForm = document.getElementById('loginForm');
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            const errorMsg = document.getElementById('loginError');

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                const data = await res.json();
                
                if (data.success) {
                    // Intentionally insecure: storing token in localStorage
                    localStorage.setItem('corp_token', data.token);
                    window.location.href = data.redirect;
                } else {
                    errorMsg.textContent = data.message || 'Login failed';
                    errorMsg.style.display = 'block';
                }
            } catch (err) {
                errorMsg.textContent = 'Network error occurred';
                errorMsg.style.display = 'block';
            }
        });
    }

    // --- Logout ---
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            localStorage.removeItem('corp_token');
            window.location.href = '/';
        });
    }

    // --- Protected Routes Checking (Client Side Only - Insecure!) ---
    if (path.includes('/admin/')) {
        // We only weakly check if local storage has *something*, no validation!
        if (!token && !path.includes('dashboard.html')) {
            // Dashboard is completely exposed by design. Other pages check loosely.
            console.warn("No token found, but allowing access to demonstrate frontend insecure routing");
        }
    }

    // --- Dashboard Charts ---
    if (document.getElementById('revenueChart')) {
        const revCtx = document.getElementById('revenueChart').getContext('2d');
        new Chart(revCtx, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                datasets: [{
                    label: 'Revenue ($)',
                    data: [32000, 38000, 25000, 42000, 41000, 45200],
                    borderColor: '#3b82f6',
                    tension: 0.4,
                    fill: true,
                    backgroundColor: 'rgba(59, 130, 246, 0.1)'
                }]
            },
            options: { responsive: true, color: '#94a3b8', scales: { y: { grid: { color: '#334155' } }, x: { grid: { color: '#334155' } } } }
        });

        const userCtx = document.getElementById('userGrowthChart').getContext('2d');
        new Chart(userCtx, {
            type: 'bar',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                datasets: [{
                    label: 'New Users',
                    data: [120, 150, 180, 220, 170, 250],
                    backgroundColor: '#10b981'
                }]
            },
            options: { responsive: true, color: '#94a3b8', scales: { y: { grid: { color: '#334155' } }, x: { grid: { color: '#334155' } } } }
        });
    }

    // --- User Management ---
    const usersTableBody = document.getElementById('usersTableBody');
    if (usersTableBody) {
        const fetchUsers = async () => {
            try {
                const res = await fetch('/api/users', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                const users = await res.json();
                
                usersTableBody.innerHTML = users.map(u => `
                    <tr>
                        <td>#${u.id.toString().padStart(4, '0')}</td>
                        <td><strong>${u.name}</strong></td>
                        <td>${u.email}</td>
                        <td><span class="badge ${u.role}">${u.role}</span></td>
                        <td>${u.lastLogin}</td>
                        <td>
                            <button class="btn-edit" onclick="openEditModal(${u.id}, '${u.role}')">Change Role</button>
                        </td>
                    </tr>
                `).join('');
            } catch (err) {
                console.error("Failed to load users", err);
            }
        };

        fetchUsers();

        // Modal Logic
        const modal = document.getElementById('editRoleModal');
        const span = document.getElementsByClassName('close')[0];
        const editForm = document.getElementById('editRoleForm');

        window.openEditModal = (id, currentRole) => {
            document.getElementById('editUserId').value = id;
            document.getElementById('newRole').value = currentRole;
            modal.style.display = "block";
        };

        span.onclick = () => modal.style.display = "none";
        window.onclick = (e) => { if (e.target == modal) modal.style.display = "none"; }

        // Privilege Escalation Exploit
        editForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const id = document.getElementById('editUserId').value;
            const newRole = document.getElementById('newRole').value;
            const msg = document.getElementById('roleUpdateMsg');

            try {
                // Anyone can call this! No backend authz checks.
                const res = await fetch(`/api/users/${id}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token || 'fake-token'}`
                    },
                    body: JSON.stringify({ role: newRole })
                });
                
                const data = await res.json();
                if (data.success) {
                    msg.style.color = '#10b981';
                    msg.textContent = 'Role updated successfully! (Privilege Escalated)';
                    setTimeout(() => {
                        modal.style.display = "none";
                        msg.textContent = '';
                        fetchUsers(); // refresh
                    }, 1500);
                } else {
                    msg.style.color = '#ef4444';
                    msg.textContent = 'Failed: ' + (data.error || 'Unknown error');
                }
            } catch (err) {
                msg.textContent = 'API Error occurred';
            }
        });
    }

    // --- Settings / System Info / Debug ---
    const sysInfoDiv = document.getElementById('systemInfo');
    if (sysInfoDiv) {
        const fetchSysInfo = async () => {
            try {
                const res = await fetch('/api/system-info', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                const data = await res.json();
                
                let depsHtml = '<ul class="deps-list">';
                if (data.dependencies) {
                    for (const [pkg, ver] of Object.entries(data.dependencies)) {
                        depsHtml += `<li>${pkg}: <span>${ver}</span></li>`;
                    }
                }
                depsHtml += '</ul>';

                sysInfoDiv.innerHTML = `
                    <p><strong>Service:</strong> ${data.serviceName}</p>
                    <p><strong>Uptime:</strong> ${Math.floor(data.uptime)} seconds</p>
                    <p><strong>Node Modules:</strong> (Warning: Outdated packages detected)</p>
                    ${depsHtml}
                `;
            } catch (err) {
                sysInfoDiv.innerHTML = `<p style="color:red">Failed to load system info</p>`;
            }
        };
        fetchSysInfo();
    }

    const triggerErrorBtn = document.getElementById('triggerErrorBtn');
    const errorDisplay = document.getElementById('errorDisplay');
    if (triggerErrorBtn) {
        triggerErrorBtn.addEventListener('click', async () => {
            errorDisplay.textContent = "Fetching debug logs...\n";
            try {
                const res = await fetch('/api/debug');
                const data = await res.json();
                // Dump raw error stack and environment variables to the UI
                errorDisplay.textContent += `== EXCEPTION CAUGHT ==\n${data.error}\n\n`;
                errorDisplay.textContent += `== STACK TRACE ==\n${data.stack}\n\n`;
                errorDisplay.textContent += `== ENVIRONMENT (Exposed Credentials) ==\n${JSON.stringify(data.env, null, 2)}\n\n`;
                errorDisplay.textContent += `== PROCESS INFO ==\n${JSON.stringify(data.process, null, 2)}`;
            } catch (err) {
                errorDisplay.textContent = 'Failed to trigger debug endpoint.';
            }
        });
    }
});
