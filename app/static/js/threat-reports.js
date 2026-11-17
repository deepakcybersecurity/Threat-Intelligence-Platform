/* ==========================================================
   THREAT REPORTS MODULE - PART 1
   --------------------------------------------
   Features
   ✔ Live Search
   ✔ Severity Filter
   ✔ Category Filter
   ✔ Status Filter
   ✔ Report Counter
========================================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ==========================================
       Get Elements
    ========================================== */

    const searchInput =
        document.querySelector('input[name="search"]');

    const severityFilter =
        document.querySelector('select[name="severity"]');

    const categoryFilter =
        document.querySelector('select[name="category"]');

    const statusFilter =
        document.querySelector('select[name="status"]');

    const reportsTable =
        document.querySelector(".data-table");

    if (!reportsTable) return;

    const tableRows =
        reportsTable.querySelectorAll("tbody tr");



    /* ==========================================
       Report Counter
    ========================================== */

    const counter = document.createElement("div");

    counter.className = "report-counter";

    counter.style.marginBottom = "15px";

    counter.style.fontWeight = "600";

    counter.style.color = "#cbd5e1";

    reportsTable.parentNode.insertBefore(
        counter,
        reportsTable
    );



    /* ==========================================
       Update Counter
    ========================================== */

    function updateCounter() {

        const visibleRows = [...tableRows].filter(row =>
            row.style.display !== "none"
        ).length;

        counter.textContent =
            `Showing ${visibleRows} Report(s)`;

    }



    /* ==========================================
       Main Filter Function
    ========================================== */

    function filterReports() {

        const searchText =
            searchInput.value.toLowerCase();

        const severity =
            severityFilter.value.toLowerCase();

        const category =
            categoryFilter.value.toLowerCase();

        const status =
            statusFilter.value.toLowerCase();


        tableRows.forEach(row => {

            if (row.children.length < 10)
                return;

            const title =
                row.cells[1].textContent.toLowerCase();

            const rowCategory =
                row.cells[2].textContent.toLowerCase();

            const rowSeverity =
                row.cells[3].textContent.toLowerCase();

            const rowStatus =
                row.cells[0].textContent.toLowerCase();


            const searchMatch =
                title.includes(searchText);

            const severityMatch =
                severity === "" ||
                rowSeverity.includes(severity);

            const categoryMatch =
                category === "" ||
                rowCategory.includes(category);

            const statusMatch =
                status === "" ||
                rowStatus.includes(status);


            if (
                searchMatch &&
                severityMatch &&
                categoryMatch &&
                statusMatch
            ) {

                row.style.display = "";

            }

            else {

                row.style.display = "none";

            }

        });

        updateCounter();
        toggleEmptyState();

    }




    /* ==========================================
       Events
    ========================================== */

    searchInput.addEventListener(
        "keyup",
        filterReports
    );

    severityFilter.addEventListener(
        "change",
        filterReports
    );

    categoryFilter.addEventListener(
        "change",
        filterReports
    );

    statusFilter.addEventListener(
        "change",
        filterReports
    );



    /* ==========================================
       Initial Counter
    ========================================== */

    updateCounter();

});

/* ==========================================
   Reset Filters
========================================== */

function resetFilters() {

    searchInput.value = "";
    severityFilter.selectedIndex = 0;
    categoryFilter.selectedIndex = 0;
    statusFilter.selectedIndex = 0;

    filterReports();

}


/* ==========================================
   Create Reset Button
========================================== */

const filterForm = document.querySelector(".search-form-block");

if (filterForm) {

    const resetBtn = document.createElement("button");

    resetBtn.type = "button";

    resetBtn.className = "btn btn-secondary";

    resetBtn.textContent = "Reset Filters";

    resetBtn.style.marginTop = "20px";

    resetBtn.addEventListener("click", resetFilters);

    filterForm.appendChild(resetBtn);

}


/* ==========================================
   Empty State
========================================== */

const emptyMessage = document.createElement("div");

emptyMessage.className = "empty-state";

emptyMessage.innerHTML = `
    <h3>No Reports Found</h3>
    <p>Try changing your search or filters.</p>
`;

emptyMessage.style.display = "none";

reportsTable.parentNode.appendChild(emptyMessage);


function toggleEmptyState() {

    const visibleRows = [...tableRows].filter(row =>
        row.style.display !== "none"
    );

    if (visibleRows.length === 0) {

        reportsTable.style.display = "none";
        emptyMessage.style.display = "block";

    } else {

        reportsTable.style.display = "";
        emptyMessage.style.display = "none";

    }

}


/* ==========================================
   Delete Confirmation
========================================== */

document.querySelectorAll(".btn-danger").forEach(button => {

    button.addEventListener("click", function (e) {

        const confirmDelete = confirm(
            "Are you sure you want to delete this Threat Report?"
        );

        if (!confirmDelete) {

            e.preventDefault();

        } else {

            showToast("Threat Report deleted successfully.");

        }

    });

});


/* ==========================================
   Toast Notification
========================================== */

function showToast(message) {

    const toast = document.createElement("div");

    toast.className = "toast-message";

    toast.textContent = message;

    document.body.appendChild(toast);

    setTimeout(() => {

        toast.classList.add("show");

    }, 100);

    setTimeout(() => {

        toast.classList.remove("show");

        setTimeout(() => {

            toast.remove();

        }, 300);

    }, 2500);

}

/* ==========================================================
   THREAT REPORTS MODULE - PART 3
   --------------------------------------------
   Features
   ✔ Table Sorting
   ✔ Row Hover Animation
   ✔ Future Ready Button Handlers
   ✔ Keyboard Shortcut (Ctrl + F)
========================================================== */


/* ==========================================
   Table Sorting
========================================== */

const tableHeaders = document.querySelectorAll(".data-table thead th");

tableHeaders.forEach((header, index) => {

    if (index === 9) return;

    header.style.cursor = "pointer";

    header.addEventListener("click", () => {

        sortTable(index);

    });

});


function sortTable(columnIndex) {

    const tbody = reportsTable.querySelector("tbody");

    const rows = Array.from(tbody.querySelectorAll("tr"));

    const sortedRows = rows.sort((a, b) => {

        const textA = a.cells[columnIndex].textContent.trim().toLowerCase();

        const textB = b.cells[columnIndex].textContent.trim().toLowerCase();

        return textA.localeCompare(textB);

    });

    tbody.innerHTML = "";

    sortedRows.forEach(row => {

        tbody.appendChild(row);

    });

}


/* ==========================================
   Row Hover Effect
========================================== */

tableRows.forEach(row => {

    row.addEventListener("mouseenter", () => {

        row.style.transition = "0.3s";

        row.style.transform = "scale(1.01)";

    });

    row.addEventListener("mouseleave", () => {

        row.style.transform = "scale(1)";

    });

});


/* ==========================================
   View Button (Future Ready)
========================================== */

document.querySelectorAll(".btn-secondary").forEach(button => {

    button.addEventListener("click", () => {

        showToast("View feature will be connected with Flask backend.");

    });

});


/* ==========================================
   Edit Button (Future Ready)
========================================== */

document.querySelectorAll(".btn-warning").forEach(button => {

    button.addEventListener("click", () => {

        showToast("Edit feature will be available after CRUD integration.");

    });

});


/* ==========================================
   Download Placeholder
========================================== */

document.querySelectorAll("tbody tr").forEach(row => {

    const attachmentCell = row.cells[8];

    if (!attachmentCell) return;

    attachmentCell.style.cursor = "pointer";

    attachmentCell.title = "Download attachment";

    attachmentCell.addEventListener("click", () => {

        showToast("Download feature coming soon.");

    });

});


/* ==========================================
   Keyboard Shortcut
========================================== */

document.addEventListener("keydown", (e) => {

    if (e.ctrlKey && e.key.toLowerCase() === "f") {

        e.preventDefault();

        searchInput.focus();

    }

});


/* ==========================================
   Page Loaded Notification
========================================== */

window.addEventListener("load", () => {

    setTimeout(() => {

        showToast("Threat Reports loaded successfully.");

    }, 500);

});

