document.addEventListener('DOMContentLoaded', function() {
    // Toggle password visibility for password fields
    const togglePasswordButtons = document.querySelectorAll('.toggle-password');
    togglePasswordButtons.forEach(button => {
        button.addEventListener('click', function() {
            const passwordField = document.querySelector(this.getAttribute('data-target'));
            const type = passwordField.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordField.setAttribute('type', type);
            
            // Toggle icon
            this.querySelector('i').classList.toggle('fa-eye');
            this.querySelector('i').classList.toggle('fa-eye-slash');
        });
    });
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Handle ledger entry form validation
    const ledgerEntryForm = document.getElementById('ledgerEntryForm');
    if (ledgerEntryForm) {
        ledgerEntryForm.addEventListener('submit', function(event) {
            const connectedUserSelect = document.getElementById('connected_user');
            if (connectedUserSelect.value === '0') {
                event.preventDefault();
                alert('Please select a connected user for this transaction.');
            }
        });
    }
    
    // Format currency amounts
    const currencyElements = document.querySelectorAll('.currency');
    currencyElements.forEach(element => {
        const amount = parseFloat(element.textContent);
        element.textContent = amount.toLocaleString('en-US', {
            style: 'currency',
            currency: 'USD'
        });
    });
    
    // Show confirmation dialog for dangerous actions
    const dangerousActions = document.querySelectorAll('.confirm-action');
    dangerousActions.forEach(element => {
        element.addEventListener('click', function(event) {
            if (!confirm('Are you sure you want to perform this action?')) {
                event.preventDefault();
            }
        });
    });
});

// Toggle between dummy data and real data views
function toggleDataView() {
    const isDummy = document.getElementById('dataViewStatus').value === 'true';
    const statusText = document.getElementById('dataViewText');
    
    if (isDummy) {
        statusText.textContent = 'DUMMY DATA VIEW';
        statusText.classList.add('text-warning');
    } else {
        statusText.textContent = 'REAL DATA VIEW';
        statusText.classList.add('text-success');
    }
}

// Function to confirm dangerous actions
function confirmAction(message) {
    return confirm(message || 'Are you sure you want to perform this action?');
}
