document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('loginForm');

    loginForm.addEventListener('submit', function(event) {
        event.preventDefault();

        const username = document.querySelector('input[name="username"]').value;
        const password = document.querySelector('input[name="password"]').value;
        const rememberMe = document.getElementById('remember').checked;

        // Kirim data formulir ke server menggunakan Fetch API
        fetch('api/admin_login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password,
                rememberMe: rememberMe
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Jika login berhasil, redirect ke halaman admin
                window.location.href = '/admin';
            } else {
                // Jika login gagal, tampilkan pesan error menggunakan SweetAlert
                Swal.fire({
                    title: 'Error',
                    text: data.message,
                    icon: 'error',
                    confirmButtonText: 'OK'
                });
            }
        })
        .catch(error => {
            // Tangani kesalahan jaringan atau server
            console.error('Error:', error);
            Swal.fire({
                title: 'Error',
                text: 'There was an error processing your request. Please try again later.',
                icon: 'error',
                confirmButtonText: 'OK'
            });
        });
    });
});
