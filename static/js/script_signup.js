document.addEventListener('DOMContentLoaded', function() {
    const signupForm = document.getElementById('signupForm');

    signupForm.addEventListener('submit', function(event) {
        event.preventDefault();

        const username = document.querySelector('input[name="username"]').value;
        const password = document.querySelector('input[name="password"]').value;
        const confirmPassword = document.querySelector('input[name="confirm_password"]').value;

        // Validasi password dan konfirmasi password
        if (password !== confirmPassword) {
            Swal.fire({
                title: 'Error!',
                text: 'Password dan konfirmasi password tidak cocok.',
                icon: 'error',
            });
            return;
        }

        // Kirim data ke server untuk pendaftaran
        fetch('/api/admin_register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username: username, password: password }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Pendaftaran berhasil, tampilkan pesan sukses dan redirect ke halaman login
                Swal.fire({
                    title: 'Success!',
                    text: 'Pendaftaran berhasil! Silakan login untuk melanjutkan.',
                    icon: 'success',
                }).then((result) => {
                    if (result.isConfirmed || result.isDismissed) {
                        window.location.href = '/admin';
                    }
                });
            } else {
                // Pendaftaran gagal, tampilkan pesan error
                Swal.fire({
                    title: 'Error!',
                    text: 'Pendaftaran gagal. ' + data.message,
                    icon: 'error',
                });
            }
        })
        .catch(error => {
            // Tangani kesalahan yang terjadi selama proses pengiriman data
            console.error('Error:', error);
            Swal.fire({
                title: 'Error!',
                text: 'Terjadi kesalahan saat mengirim data pendaftaran. Silakan coba lagi.',
                icon: 'error',
            });
        });
    });
});
