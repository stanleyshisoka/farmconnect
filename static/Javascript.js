<script>
        // Tab switching functionality
        function switchTab(tab) {
            // Update active tab button
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            event.target.classList.add('active');
            
            // Show appropriate form
            if (tab === 'farmer') {
                document.getElementById('farmer-form').style.display = 'block';
                document.getElementById('consumer-form').style.display = 'none';
            } else {
                document.getElementById('farmer-form').style.display = 'none';
                document.getElementById('consumer-form').style.display = 'block';
            }
        }
        
        // Show login section when login button is clicked
        function showLogin() {
            document.getElementById('login').scrollIntoView({ behavior: 'smooth' });
        }
        
        // Show login section with registration forms when register button is clicked
        function showRegister() {
            document.getElementById('login').scrollIntoView({ behavior: 'smooth' });
        }
        
        // Form submission handling
        document.getElementById('farmer-form').addEventListener('submit', function(e) {
            e.preventDefault();
            alert('Farmer login submitted! This would connect to the backend in a real application.');
            // Here you would typically send the data to your Flask backend
        });
        
        document.getElementById('consumer-form').addEventListener('submit', function(e) {
            e.preventDefault();
            alert('Consumer login submitted! This would connect to the backend in a real application.');
            // Here you would typically send the data to your Flask backend
        });
        
        // Mobile menu toggle
        document.querySelector('.mobile-menu-btn').addEventListener('click', function() {
            const navLinks = document.querySelector('.nav-links');
            const authButtons = document.querySelector('.auth-buttons');
            
            if (navLinks.style.display === 'flex') {
                navLinks.style.display = 'none';
                authButtons.style.display = 'none';
            } else {
                navLinks.style.display = 'flex';
                authButtons.style.display = 'block';
                
                // Adjust for mobile view
                navLinks.style.flexDirection = 'column';
                navLinks.style.position = 'absolute';
                navLinks.style.top = '70px';
                navLinks.style.left = '0';
                navLinks.style.width = '100%';
                navLinks.style.backgroundColor = 'white';
                navLinks.style.padding = '20px';
                navLinks.style.boxShadow = '0 5px 10px rgba(0,0,0,0.1)';
                
                authButtons.style.position = 'absolute';
                authButtons.style.top = '220px';
                authButtons.style.left = '0';
                authButtons.style.width = '100%';
                authButtons.style.padding = '0 20px 20px';
                authButtons.style.backgroundColor = 'white';
            }
        });
</script>
