document.addEventListener("DOMContentLoaded", function () {
    const navLinks = document.querySelectorAll(".nav-link");

    navLinks.forEach(link => {
        link.addEventListener("click", function () {
            // Remove the 'active' class from all nav-links
            navLinks.forEach(nav => nav.classList.remove("active"));
            
            // Add the 'active' class to the clicked nav-link
            this.classList.add("active");
        });
    });
});
