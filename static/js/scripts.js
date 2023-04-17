function showAddCafeLink() {
    if (isLoggedIn()) {
        document.getElementById('add-cafe-item').style.display = 'block';
    } else {
        document.getElementById('add-cafe-item').style.display = 'none';
    }
}

showAddCafeLink(); // Call this function on page load
