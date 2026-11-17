document.addEventListener("DOMContentLoaded", () => {

    const deleteForm = document.querySelector(".delete-form");

    if (!deleteForm) return;

    deleteForm.addEventListener("submit", function (event) {

        const confirmed = confirm(
            "Are you sure you want to permanently delete this Threat Report?\n\nThis action cannot be undone."
        );

        if (!confirmed) {

            event.preventDefault();

        }

    });

});