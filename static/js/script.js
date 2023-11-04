document.addEventListener("DOMContentLoaded", function() {
    const descriptions = document.querySelectorAll(".description");
    const readMoreButtons = document.querySelectorAll(".read-more-btn");
    const buyButtons = document.querySelectorAll(".buy-btn");

    readMoreButtons.forEach((button, index) => {
        button.addEventListener("click", function() {
            descriptions[index].classList.toggle("expanded");
            if (descriptions[index].classList.contains("expanded")) {
                button.textContent = "Read less";
            } else {
                button.textContent = "Read more";
            }
        });
    });

    buyButtons.forEach(button => {
        button.addEventListener("click", function(event) {
            event.preventDefault();
            const productId = button.getAttribute("data-product-id");
            const pointCost = button.getAttribute("data-point-cost");

            // Kirim permintaan ke server menggunakan AJAX
            fetch("/redeem_product", {
                method: "POST",
                body: JSON.stringify({ product_id: productId, point_cost: pointCost }),
                headers: {
                    "Content-Type": "application/json"
                }
            })
            .then(response => response.json())
            .then(data => {
                // Tampilkan pesan balasan dari server
                alert(data.message);

                // Refresh halaman jika redeemsukses
                if (data.success) {
                    location.reload();
                }
            })
            .catch(error => {
                console.error("Error:", error);
            });
        });
    });
});

