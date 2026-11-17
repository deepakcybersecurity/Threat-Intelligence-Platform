document.addEventListener("DOMContentLoaded", () => {
    
    // ==========================================================================
    // 1. GLOBAL TOAST NOTIFICATION SYSTEM
    // ==========================================================================
    function showToast(message, type = "success") {
        let container = document.querySelector(".notification-container");
        if (!container) {
            container = document.createElement("div");
            container.className = "notification-container";
            // Dynamically inject structural CSS for notification container if needed,
            // though style.css handles styling. Let's enforce layout.
            container.setAttribute("style", "position: fixed; bottom: 20px; right: 20px; display: flex; flex-direction: column; gap: 10px; z-index: 9999; max-width: 350px;");
            document.body.appendChild(container);
        }

        const notification = document.createElement("div");
        notification.className = `notification badge-${type}`;
        
        // Dynamic styling for notification card
        let borderCol = "var(--status-success)";
        if (type === "critical" || type === "danger") borderCol = "var(--status-critical)";
        if (type === "warning") borderCol = "var(--status-warning)";
        if (type === "info") borderCol = "var(--status-info)";

        notification.setAttribute("style", `
            background-color: var(--bg-secondary);
            color: var(--text-main);
            border: 1px solid var(--border-color);
            border-left: 4px solid ${borderCol};
            padding: 1rem 1.25rem;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-lg);
            font-size: 0.9rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            transform: translateX(120%);
            transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        `);

        notification.innerHTML = `
            <span>${message}</span>
            <button class="toast-close-btn" style="background: none; border: none; color: var(--text-muted); cursor: pointer; font-size: 1rem;">&times;</button>
        `;

        container.appendChild(notification);

        // Slide in
        setTimeout(() => {
            notification.style.transform = "translateX(0)";
        }, 50);

        // Close button click handler
        notification.querySelector(".toast-close-btn").addEventListener("click", () => {
            dismissNotification(notification);
        });

        // Auto dismiss after 4 seconds
        const autoDismissTimer = setTimeout(() => {
            dismissNotification(notification);
        }, 4000);

        function dismissNotification(el) {
            el.style.transform = "translateX(120%)";
            setTimeout(() => {
                el.remove();
            }, 300);
            clearTimeout(autoDismissTimer);
        }
    }

    // Welcome greeting
    setTimeout(() => {
        showToast("SecOps Environment initialized. Auditing active.", "info");
    }, 800);


    // ==========================================================================
    // 2. RESPONSIVE NAVIGATION & MOBILE MENU TOGGLE
    // ==========================================================================
    const sidebar = document.querySelector(".sidebar");
    const header = document.querySelector(".main-header");
    
    // Add mobile toggle button dynamically if on a dashboard page
    if (sidebar && header) {
        const toggleContainer = document.createElement("div");
        toggleContainer.className = "mobile-toggle-wrapper";
        toggleContainer.setAttribute("style", "display: none; padding: 0.5rem;");
        
        const toggleBtn = document.createElement("button");
        toggleBtn.className = "btn btn-secondary";
        toggleBtn.innerHTML = "&#9776; Menu";
        toggleBtn.setAttribute("style", "padding: 0.4rem 0.8rem; font-size: 0.85rem;");
        
        toggleContainer.appendChild(toggleBtn);
        header.querySelector(".navbar").insertBefore(toggleContainer, header.querySelector(".navbar-search") || header.querySelector(".navbar-actions"));

        // CSS Media Queries will display/hide this. We can force display:block via dynamic style tag
        const mediaStyle = document.createElement("style");
        mediaStyle.textContent = `
            @media (max-width: 768px) {
                .mobile-toggle-wrapper { display: block !important; }
            }
        `;
        document.head.appendChild(mediaStyle);

        toggleBtn.addEventListener("click", () => {
            if (sidebar.style.display === "none" || sidebar.style.display === "") {
                sidebar.style.display = "block";
                sidebar.setAttribute("style", "width: 100%; border-bottom: 1px solid var(--border-color);");
            } else {
                sidebar.style.display = "none";
            }
        });
    }


    // ==========================================================================
    // 3. DASHBOARD MOCK LIVE METRIC FLUCTUATIONS
    // ==========================================================================
    const dashboardGrid = document.querySelector(".dashboard-cards-grid");
    if (dashboardGrid && window.location.pathname.includes("dashboard.html")) {
        setInterval(() => {
            const cards = dashboardGrid.querySelectorAll(".dashboard-card");
            
            // Randomly update CPU/Log ingestion if exists (admin panel), or active counts
            cards.forEach(card => {
                const title = card.querySelector("h2")?.textContent || card.querySelector("h3")?.textContent;
                const valueEl = card.querySelector(".card-value") || card.querySelector("p strong");
                
                if (title && valueEl) {
                    if (title.includes("Blocked IP")) {
                        let current = parseInt(valueEl.textContent.replace(/,/g, ''));
                        if (Math.random() > 0.6) {
                            current += Math.floor(Math.random() * 3) + 1;
                            valueEl.textContent = current.toLocaleString();
                            showToast(`Perimeter Firewall: Blocked host added to ban list.`, "info");
                        }
                    } else if (title.includes("Ingestion")) {
                        let current = parseInt(valueEl.textContent.replace(/[^0-9]/g, ''));
                        current += Math.floor(Math.random() * 50) - 25;
                        valueEl.textContent = `${current} eps`;
                    }
                }
            });
        }, 12000);
    }


    // ==========================================================================
    // 4. LIVE TABLE SEARCH FILTERING
    // ==========================================================================
    const searchInputs = document.querySelectorAll(".search-input");
    const dataTables = document.querySelectorAll(".data-table");

    if (searchInputs.length > 0 && dataTables.length > 0) {
        searchInputs.forEach(input => {
            input.addEventListener("input", (e) => {
                const query = e.target.value.toLowerCase().trim();
                
                dataTables.forEach(table => {
                    const rows = table.querySelectorAll("tbody tr");
                    rows.forEach(row => {
                        // Skip empty state rows if they exist
                        if (row.classList.contains("empty-state-row")) return;
                        
                        const text = row.textContent.toLowerCase();
                        if (text.includes(query)) {
                            row.style.display = "";
                        } else {
                            row.style.display = "none";
                        }
                    });
                });
            });
        });
    }


    // ==========================================================================
    // 5. IP ADDRESS REPUTATION CHECKER SCAN SIMULATOR
    // ==========================================================================
    // const ipForm = document.querySelector(".search-form-block");
    // const statusAlert = document.querySelector(".threat-status-alert");
    // const analysisGrid = document.querySelector(".ip-analysis-grid");
    // const blocklistSection = document.querySelector(".blocklist-details-section");

    // if (ipForm && statusAlert && analysisGrid) {
    //     // Intercept form submissions
    //     ipForm.addEventListener("submit", (e) => {
    //         e.preventDefault();
            
    //         const ipInput = ipForm.querySelector("#ip-address");
    //         const ipVal = ipInput.value.trim();
            
    //         if (!ipVal) return;

    //         // Hide old stats to show scanning animation
    //         statusAlert.style.display = "none";
    //         analysisGrid.style.opacity = "0.3";
    //         if (blocklistSection) blocklistSection.style.opacity = "0.3";

    //         showToast(`Initiating threat validation on ${ipVal}...`, "info");

    //         // Build dynamic loading indicator
    //         const loader = document.createElement("div");
    //         loader.className = "scanning-loader";
    //         loader.setAttribute("style", "text-align: center; padding: 3rem; background: var(--bg-secondary); border-radius: var(--radius-lg); border: 1px dashed var(--border-color); margin-bottom: 2rem;");
    //         loader.innerHTML = `
    //             <div class="spinner" style="width: 40px; height: 40px; border: 4px solid var(--border-color); border-top: 4px solid var(--accent-cyan); border-radius: 50%; animation: spin 1s linear infinite; margin: 0 auto 1rem auto;"></div>
    //             <strong>Querying Global Indicators...</strong>
    //             <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 0.5rem;" class="scanning-step">Parsing ASN routing tables...</p>
    //         `;
            
    //         // Add keyframes for spinner dynamically
    //         if (!document.getElementById("spinner-keyframes")) {
    //             const keyframes = document.createElement("style");
    //             keyframes.id = "spinner-keyframes";
    //             keyframes.textContent = "@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }";
    //             document.head.appendChild(keyframes);
    //         }

    //         ipForm.parentNode.insertBefore(loader, statusAlert);

    //         // Simulation step triggers
    //         const steps = [
    //             "Resolving geo-coordinates...",
    //             "Querying Abuse.ch URLhaus DNSBL...",
    //             "Scanning Honeypot honeynet logs...",
    //             "Checking Cisco Talos classification..."
    //         ];
            
    //         let stepIndex = 0;
    //         const stepInterval = setInterval(() => {
    //             if (stepIndex < steps.length) {
    //                 loader.querySelector(".scanning-step").textContent = steps[stepIndex];
    //                 stepIndex++;
    //             } else {
    //                 clearInterval(stepInterval);
    //             }
    //         }, 600);

    //         // Complete simulation
    //         setTimeout(() => {
    //             loader.remove();
                
    //             // Set details
    //             const isMalicious = !ipVal.startsWith("192.168.") && !ipVal.startsWith("10.") && !ipVal.startsWith("127.0.");
                
    //             // Update elements based on check result
    //             if (isMalicious) {
    //                 statusAlert.className = "threat-status-alert danger-alert";
    //                 statusAlert.querySelector(".alert-heading").textContent = "Malicious Activity Detected!";
    //                 statusAlert.querySelector(".alert-body").innerHTML = `IP address <strong>${ipVal}</strong> is flagged on multiple active threat blocklists.`;
                    
    //                 // Update table
    //                 const detailsTable = analysisGrid.querySelector(".details-table tbody");
    //                 if (detailsTable) {
    //                     detailsTable.innerHTML = `
    //                         <tr>
    //                             <th scope="row">IP Address</th>
    //                             <td><code>${ipVal}</code></td>
    //                         </tr>
    //                         <tr>
    //                             <th scope="row">IP Version</th>
    //                             <td>IPv4</td>
    //                         </tr>
    //                         <tr>
    //                             <th scope="row">Internet Service Provider</th>
    //                             <td>Global Security Hosting Inc.</td>
    //                         </tr>
    //                         <tr>
    //                             <th scope="row">Organization / ASN</th>
    //                             <td>ASN42011 (Malicious Proxy Network)</td>
    //                         </tr>
    //                         <tr>
    //                             <th scope="row">Geographic Country</th>
    //                             <td>Netherlands (NL)</td>
    //                         </tr>
    //                         <tr>
    //                             <th scope="row">City / Region</th>
    //                             <td>Amsterdam</td>
    //                         </tr>
    //                         <tr>
    //                             <th scope="row">Domain Hostname</th>
    //                             <td><code>host-${ipVal.replace(/\./g, '-')}.nl</code></td>
    //                         </tr>
    //                     `;
    //                 }

    //                 // Update score
    //                 const scoreVal = analysisGrid.querySelector(".score-value");
    //                 if (scoreVal) {
    //                     scoreVal.className = "score-value critical-score";
    //                     scoreVal.textContent = "87 / 100";
    //                 }
    //                 showToast(`Scan complete: Host ${ipVal} has HIGH threat scoring.`, "critical");
    //             } else {
    //                 statusAlert.className = "threat-status-alert";
    //                 statusAlert.setAttribute("style", "border-left: 4px solid var(--status-success); background-color: rgba(16, 185, 129, 0.1); padding: 1.5rem; border-radius: var(--radius-lg); margin-bottom: 2rem;");
    //                 statusAlert.querySelector(".alert-heading").style.color = "var(--status-success)";
    //                 statusAlert.querySelector(".alert-heading").textContent = "Host Reputable (Secure)";
    //                 statusAlert.querySelector(".alert-body").innerHTML = `IP address <strong>${ipVal}</strong> shows clean history logs and zero blocklist counts.`;
                    
    //                 // Update table
    //                 const detailsTable = analysisGrid.querySelector(".details-table tbody");
    //                 if (detailsTable) {
    //                     detailsTable.innerHTML = `
    //                         <tr>
    //                             <th scope="row">IP Address</th>
    //                             <td><code>${ipVal}</code></td>
    //                         </tr>
    //                         <tr>
    //                             <th scope="row">IP Version</th>
    //                             <td>IPv4</td>
    //                         </tr>
    //                         <tr>
    //                             <th scope="row">Internet Service Provider</th>
    //                             <td>Local Intranet Network</td>
    //                         </tr>
    //                         <tr>
    //                             <th scope="row">Organization / ASN</th>
    //                             <td>Internal Systems Range</td>
    //                         </tr>
    //                         <tr>
    //                             <th scope="row">Geographic Country</th>
    //                             <td>Local Loopback</td>
    //                         </tr>
    //                         <tr>
    //                             <th scope="row">City / Region</th>
    //                             <td>Local Intranet</td>
    //                         </tr>
    //                         <tr>
    //                             <th scope="row">Domain Hostname</th>
    //                             <td><code>internal-system.local</code></td>
    //                         </tr>
    //                     `;
    //                 }

    //                 // Update score
    //                 const scoreVal = analysisGrid.querySelector(".score-value");
    //                 if (scoreVal) {
    //                     scoreVal.className = "score-value";
    //                     scoreVal.setAttribute("style", "color: var(--status-success); font-size: 3rem; font-weight: 800;");
    //                     scoreVal.textContent = "0 / 100";
    //                 }
    //                 showToast(`Scan complete: Host ${ipVal} is secure.`, "success");
    //             }

    //             // Restore visibility
    //             statusAlert.style.display = "flex";
    //             analysisGrid.style.opacity = "1";
    //             if (blocklistSection) blocklistSection.style.opacity = "1";
    //         }, 3000);
    //     });
    // }


    // ==========================================================================
    // 6. MALWARE INFORMATION YARA COPIER
    // ==========================================================================
    const ruleContainer = document.querySelector(".code-block-container");
    if (ruleContainer) {
        const copyBtn = document.createElement("button");
        copyBtn.className = "btn btn-secondary";
        copyBtn.innerHTML = "&#128203; Copy Yara Rule";
        copyBtn.setAttribute("style", "margin-top: 1rem; padding: 0.5rem 1rem; font-size: 0.85rem;");
        
        ruleContainer.parentNode.insertBefore(copyBtn, ruleContainer.nextSibling);

        copyBtn.addEventListener("click", () => {
            const codeText = ruleContainer.querySelector("code").textContent;
            navigator.clipboard.writeText(codeText).then(() => {
                copyBtn.innerHTML = "&#9989; Copied Yara Rule!";
                showToast("Yara signature copied to clipboard.", "success");
                setTimeout(() => {
                    copyBtn.innerHTML = "&#128203; Copy Yara Rule";
                }, 2000);
            }).catch(() => {
                showToast("Failed to copy signature rules.", "warning");
            });
        });
    }


    // ==========================================================================
    // 7. THREAT REPORT UPLOAD PROGRESS INTERACTIVITY
    // ==========================================================================
    // const uploadForm = document.querySelector(".upload-form");
    // if (uploadForm) {
    //     uploadForm.addEventListener("submit", (e) => {
    //         e.preventDefault();
            
    //         const fileInput = uploadForm.querySelector("#file-upload");
    //         if (!fileInput.files || fileInput.files.length === 0) {
    //             showToast("Please choose a valid forensically verified file.", "warning");
    //             return;
    //         }

    //         const title = uploadForm.querySelector("#report-title").value.trim();
    //         const fileName = fileInput.files[0].name;

    //         const submitBtn = uploadForm.querySelector("button[type='submit']");
    //         const origText = submitBtn.textContent;
            
    //         // Show loading upload progress status
    //         submitBtn.disabled = true;
    //         submitBtn.textContent = "Uploading payload metadata...";

    //         showToast(`Uploading: ${fileName} details.`, "info");

    //         setTimeout(() => {
    //             submitBtn.textContent = "Processing and indexing IOCs...";
                
    //             setTimeout(() => {
    //                 submitBtn.disabled = false;
    //                 submitBtn.textContent = origText;
                    
    //                 showToast(`Report '${title}' successfully filed and indexed into threat DB.`, "success");
    //                 uploadForm.reset();
    //             }, 1500);
    //         }, 1500);
    //     });
    // }


    // ==========================================================================
    // 8. ALERTS PAGE ACKNOWLEDGE & RESOLUTION ACTIONS
    // ==========================================================================
    const alertList = document.querySelector(".alerts-list");
    if (alertList && window.location.pathname.includes("alerts.html")) {
        const criticalCountEl = document.querySelector(".count-critical strong");
        const warningCountEl = document.querySelector(".count-warning strong");

        alertList.addEventListener("click", (e) => {
            const btn = e.target.closest(".btn-action");
            if (!btn) return;

            e.preventDefault();
            const alertCard = btn.closest(".alert-card");
            const actionForm = btn.closest(".alert-action-form");
            const severityBadge = alertCard.querySelector(".badge");
            const isCritical = severityBadge.classList.contains("badge-critical");
            
            if (btn.value === "acknowledge") {
                // Perform Acknowledge
                btn.remove(); // Remove acknowledge button
                
                // Add status label
                const statusSpan = document.createElement("span");
                statusSpan.className = "action-status-label text-warning-status";
                statusSpan.textContent = "Under Investigation (Awaiting Audit Resolution)";
                statusSpan.setAttribute("style", "font-size: 0.9rem; font-weight: 500; margin-right: auto;");
                
                actionForm.insertBefore(statusSpan, actionForm.firstChild);
                showToast("Alert status modified: Under Investigation", "info");
            } else if (btn.value === "resolve") {
                // Perform resolution fade-out
                alertCard.style.transition = "opacity 0.4s ease, transform 0.4s ease";
                alertCard.style.opacity = "0";
                alertCard.style.transform = "scale(0.95)";
                
                setTimeout(() => {
                    alertCard.remove();
                    
                    // Decrement counters
                    if (isCritical && criticalCountEl) {
                        let val = parseInt(criticalCountEl.textContent);
                        if (val > 0) criticalCountEl.textContent = val - 1;
                    } else if (warningCountEl) {
                        let val = parseInt(warningCountEl.textContent);
                        if (val > 0) warningCountEl.textContent = val - 1;
                    }

                    showToast("Security threat alert successfully mitigated & closed.", "success");
                    
                    // Check if alert box is empty
                    if (alertList.children.length === 0) {
                        alertList.innerHTML = `
                            <article class="alert-card status-success" style="text-align:center; padding: 3rem;">
                                <h2>All Alerts Mitigated!</h2>
                                <p style="color:var(--text-muted); margin-top: 0.5rem;">Zero unhandled threats logged on perimeter sensors.</p>
                            </article>
                        `;
                    }
                }, 4000);
            }
        });
    }


    // ==========================================================================
    // 9. ADMIN PANEL USER ACCESS MANAGEMENT & AUDIT LOGS
    // ==========================================================================
    const adminUserTable = document.querySelector("section[aria-labelledby='user-mgmt-heading'] .data-table");
    if (adminUserTable && window.location.pathname.includes("admin-panel.html")) {
        adminUserTable.addEventListener("click", (e) => {
            const btn = e.target.closest(".btn-action");
            if (!btn) return;

            e.preventDefault();
            const form = btn.closest(".inline-action-form");
            const row = btn.closest("tr");
            const statusBadge = row.querySelector("td span.badge");

            if (btn.value === "suspend") {
                statusBadge.className = "badge badge-warning";
                statusBadge.textContent = "Suspended";
                
                // Modify buttons inside form
                form.innerHTML = `
                    <input type="hidden" name="user_id" value="${form.querySelector("input").value}">
                    <button type="submit" name="action" value="activate" class="btn btn-action btn-success" style="padding:0.4rem 0.8rem; font-size:0.85rem;">Re-Activate</button>
                    <button type="submit" name="action" value="delete" class="btn btn-action btn-danger" style="padding:0.4rem 0.8rem; font-size:0.85rem;">Delete</button>
                `;
                showToast("Analyst account privileges suspended.", "warning");
                appendAuditLog("Suspended User Access", row.querySelector("td strong").textContent);
            } else if (btn.value === "activate") {
                statusBadge.className = "badge badge-success";
                statusBadge.textContent = "Active";
                
                // Restore form control elements
                form.innerHTML = `
                    <input type="hidden" name="user_id" value="${form.querySelector("input").value}">
                    <select name="new_role" class="form-select select-compact" style="padding:0.4rem 0.8rem; font-size:0.85rem;">
                        <option value="admin">Admin</option>
                        <option value="tier2" selected>Tier 2 Analyst</option>
                        <option value="tier1">Tier 1 Analyst</option>
                    </select>
                    <button type="submit" name="action" value="update" class="btn btn-action btn-secondary" style="padding:0.4rem 0.8rem; font-size:0.85rem;">Apply</button>
                    <button type="submit" name="action" value="suspend" class="btn btn-action btn-warning" style="padding:0.4rem 0.8rem; font-size:0.85rem;">Suspend</button>
                `;
                showToast("Analyst permissions re-activated.", "success");
                appendAuditLog("Re-Activated User Access", row.querySelector("td strong").textContent);
            } else if (btn.value === "delete") {
                const name = row.querySelector("td strong").textContent;
                row.remove();
                showToast(`User ${name} purged from authentication directories.`, "critical");
                appendAuditLog("Deleted User Profile", name);
            } else if (btn.value === "update") {
                const selectVal = form.querySelector("select").value;
                showToast(`User role updated: ${selectVal.toUpperCase()}`, "success");
                appendAuditLog("Updated User Privileges", row.querySelector("td strong").textContent);
            }
        });

        // Handler for provisioning new analyst account
        const provisionForm = document.querySelector(".admin-card-inner form");
        if (provisionForm && provisionForm.querySelector("input[id='new-fullname']")) {
            provisionForm.addEventListener("submit", (e) => {
                e.preventDefault();
                
                const name = provisionForm.querySelector("#new-fullname").value.trim();
                const email = provisionForm.querySelector("#new-email").value.trim();
                const roleSel = provisionForm.querySelector("#new-role-select");
                const roleText = roleSel.options[roleSel.selectedIndex].text;
                
                const newId = `USR-${Math.floor(Math.random() * 90) + 10}`;

                // Add to table
                const tbody = adminUserTable.querySelector("tbody");
                const newRow = document.createElement("tr");
                newRow.innerHTML = `
                    <td>${newId}</td>
                    <td><strong>${name}</strong></td>
                    <td>${email}</td>
                    <td>${roleText}</td>
                    <td><span class="badge badge-success">Active</span></td>
                    <td>
                        <form action="admin-panel.html" method="POST" class="inline-action-form">
                            <input type="hidden" name="user_id" value="${newId}">
                            <select name="new_role" class="form-select select-compact" style="padding:0.4rem 0.8rem; font-size:0.85rem;">
                                <option value="admin">Admin</option>
                                <option value="tier2" selected>Tier 2 Analyst</option>
                                <option value="tier1">Tier 1 Analyst</option>
                            </select>
                            <button type="submit" name="action" value="update" class="btn btn-action btn-secondary" style="padding:0.4rem 0.8rem; font-size:0.85rem;">Apply</button>
                            <button type="submit" name="action" value="suspend" class="btn btn-action btn-warning" style="padding:0.4rem 0.8rem; font-size:0.85rem;">Suspend</button>
                        </form>
                    </td>
                `;
                tbody.appendChild(newRow);
                showToast(`New profile provisions successfully: ${name}`, "success");
                appendAuditLog("Provisioned Analyst Profile", name);
                provisionForm.reset();
            });
        }

        // Helper to append logs to admin panel audit trail table
        function appendAuditLog(action, target) {
            const auditTable = document.querySelector("section[aria-labelledby='audit-heading'] .data-table tbody");
            if (!auditTable) return;

            const newLogTr = document.createElement("tr");
            const nowStr = new Date().toISOString().replace('T', ' ').substring(0, 19);
            
            newLogTr.innerHTML = `
                <td>${nowStr}</td>
                <td>alice.vance@org.com</td>
                <td>${action}</td>
                <td>${target}</td>
                <td><span class="badge badge-success">Success</span></td>
            `;
            auditTable.insertBefore(newLogTr, auditTable.firstChild);
        }
    }


    // ==========================================================================
    // 10. PROFILE SECURITY TOKEN GENERATOR
    // ==========================================================================
    const tokenForm = document.querySelector(".profile-card form[action='profile.html'] .pt-form")?.parentNode;
    if (tokenForm && window.location.pathname.includes("profile.html")) {
        const tokenTable = tokenForm.parentNode.querySelector(".data-table tbody");

        tokenForm.addEventListener("submit", (e) => {
            e.preventDefault();
            
            const labelInput = tokenForm.querySelector("#new-token-label");
            const label = labelInput.value.trim();
            if (!label) return;

            // Generate fake API key token
            const randHex = Array.from({length: 24}, () => Math.floor(Math.random()*16).toString(16)).join('');
            const fakeToken = `tp_usr_${randHex.substring(0, 12)}••••••••`;

            const newRow = document.createElement("tr");
            const todayStr = new Date().toISOString().substring(0, 10);
            newRow.innerHTML = `
                <td>${label}</td>
                <td><code>${fakeToken}</code></td>
                <td>${todayStr}</td>
                <td>Never</td>
                <td>
                    <form action="profile.html" method="POST" class="inline-action-form">
                        <button type="submit" name="revoke" value="tok_gen" class="btn btn-action btn-danger" style="padding:0.4rem 0.8rem; font-size:0.85rem;">Revoke</button>
                    </form>
                </td>
            `;
            
            if (tokenTable) {
                tokenTable.appendChild(newRow);
                showToast(`New client API key token generated: ${label}`, "success");
                labelInput.value = "";
            }
        });

        // Key revocation click event
        if (tokenTable) {
            tokenTable.addEventListener("click", (e) => {
                const revokeBtn = e.target.closest("button[name='revoke']");
                if (revokeBtn) {
                    e.preventDefault();
                    const tr = revokeBtn.closest("tr");
                    const label = tr.querySelector("td").textContent;
                    tr.remove();
                    showToast(`API Client Key revoked: ${label}`, "critical");
                }
            });
        }

        // Multi-Factor Authentication preferences trigger
        const mfaSelect = document.querySelector("#mfa-type");
        if (mfaSelect) {
            mfaSelect.addEventListener("change", (e) => {
                showToast(`MFA preference changed: ${e.target.options[e.target.selectedIndex].text}`, "info");
            });
        }
    }

    // ==========================================================================
    // 16. PASSWORD VISIBILITY TOGGLE (Login, Register & Auth Forms)
    // ==========================================================================
    document.addEventListener("click", (e) => {
        const btn = e.target.closest(".password-toggle-btn");
        if (!btn) return;

        e.preventDefault();
        const wrapper = btn.closest(".password-input-wrapper");
        if (!wrapper) return;
        const input = wrapper.querySelector("input");
        if (!input) return;

        const eyeIcon = btn.querySelector(".eye-icon");
        const eyeOffIcon = btn.querySelector(".eye-off-icon");
        const isPassword = input.getAttribute("type") === "password";

        if (isPassword) {
            input.setAttribute("type", "text");
            btn.setAttribute("aria-label", "Hide password");
            btn.setAttribute("aria-pressed", "true");
            if (eyeIcon) eyeIcon.style.display = "none";
            if (eyeOffIcon) eyeOffIcon.style.display = "block";
        } else {
            input.setAttribute("type", "password");
            btn.setAttribute("aria-label", "Show password");
            btn.setAttribute("aria-pressed", "false");
            if (eyeIcon) eyeIcon.style.display = "block";
            if (eyeOffIcon) eyeOffIcon.style.display = "none";
        }

        // Keep cursor focus on the input and place cursor at end
        input.focus();
        const valLen = input.value ? input.value.length : 0;
        if (typeof input.setSelectionRange === "function") {
            input.setSelectionRange(valLen, valLen);
        }
    });
});