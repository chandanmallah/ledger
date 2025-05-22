document.addEventListener('DOMContentLoaded', function() {
    // Balance trend chart on user dashboard
    const balanceTrendCtx = document.getElementById('balanceTrendChart');
    if (balanceTrendCtx) {
        // Get data from the element's data attributes
        const balanceData = JSON.parse(balanceTrendCtx.getAttribute('data-balance'));
        const labels = JSON.parse(balanceTrendCtx.getAttribute('data-labels'));
        
        new Chart(balanceTrendCtx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Account Balance',
                    data: balanceData,
                    fill: false,
                    borderColor: '#0dcaf0',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: false
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    }
                }
            }
        });
    }
    
    // Income vs Expenses chart on user dashboard
    const incomeExpenseCtx = document.getElementById('incomeExpenseChart');
    if (incomeExpenseCtx) {
        // Get data from the element's data attributes
        const incomeData = JSON.parse(incomeExpenseCtx.getAttribute('data-income'));
        const expenseData = JSON.parse(incomeExpenseCtx.getAttribute('data-expense'));
        const labels = JSON.parse(incomeExpenseCtx.getAttribute('data-labels'));
        
        new Chart(incomeExpenseCtx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Income',
                        data: incomeData,
                        backgroundColor: '#198754',
                    },
                    {
                        label: 'Expenses',
                        data: expenseData,
                        backgroundColor: '#dc3545',
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    }
                }
            }
        });
    }
    
    // Admin dashboard user statistics chart
    const userStatsCtx = document.getElementById('userStatsChart');
    if (userStatsCtx) {
        // Get data from the element's data attributes
        const userData = JSON.parse(userStatsCtx.getAttribute('data-users'));
        const labels = JSON.parse(userStatsCtx.getAttribute('data-labels'));
        
        new Chart(userStatsCtx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: userData,
                    backgroundColor: [
                        '#0dcaf0',
                        '#198754',
                        '#dc3545',
                        '#ffc107'
                    ],
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    }
                }
            }
        });
    }
});
