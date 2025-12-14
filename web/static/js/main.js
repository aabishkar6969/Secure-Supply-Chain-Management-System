document.addEventListener('DOMContentLoaded', function() {
    const tamperBtn = document.getElementById('tamperBtn');
    if (tamperBtn) {
        tamperBtn.addEventListener('click', function(e) {
            e.preventDefault();
            if (confirm('⚠️ Simulate a tamper attack?\n\nThis will alter the shipment data to demonstrate fraud detection.')) {
                tamperBtn.innerHTML = 'Simulating...';
                tamperBtn.disabled = true;
                setTimeout(() => {
                    document.getElementById('tamperForm').submit();
                }, 500);
            }
        });
    }
    
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
});