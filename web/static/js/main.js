// static/js/main.js

document.addEventListener('DOMContentLoaded', function() {
    // Add loading indicators when forms are submitted
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitBtn = form.querySelector('button[type="submit"]');
            submitBtn.textContent = 'Processing...';
            submitBtn.disabled = true;
            
            // Optional: Add a loading spinner
            submitBtn.classList.add('loading');
        });
    });

    // Add file input preview (shows selected file names)
    const fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        input.addEventListener('change', function() {
            if (this.files.length > 0) {
                const fileName = this.files[0].name;
                const label = this.previousElementSibling; // Get the associated label
                
                if (label && label.tagName === 'LABEL') {
                    // Add a small preview of the file name
                    let preview = this.nextElementSibling;
                    if (!preview || !preview.classList.contains('file-preview')) {
                        preview = document.createElement('div');
                        preview.className = 'file-preview';
                        preview.style.fontSize = '0.9em';
                        preview.style.color = '#666';
                        preview.style.marginTop = '0.25rem';
                        this.parentNode.insertBefore(preview, this.nextSibling);
                    }
                    preview.textContent = `Selected: ${fileName}`;
                }
            }
        });
    });

    // Add auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            alert.style.transition = 'opacity 0.5s ease-out';
            setTimeout(() => {
                if (alert.parentNode) {
                    alert.parentNode.removeChild(alert);
                }
            }, 500);
        }, 5000); // 5 seconds
    });
});