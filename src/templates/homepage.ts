const homepageTemplate=`      
        
       <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Finable - The Protocol Backend</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }

                body {
                    font-family: 'Courier New', monospace;
                    background: linear-gradient(135deg, #0f0f23 0%, #1a1a2e 50%, #16213e 100%);
                    color: #e0e6ed;
                    min-height: 100vh;
                    overflow-x: hidden;
                }

                .stars {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    pointer-events: none;
                    z-index: 0;
                }

                .star {
                    position: absolute;
                    width: 2px;
                    height: 2px;
                    background: #ffffff;
                    border-radius: 50%;
                    animation: twinkle 3s infinite;
                }

                @keyframes twinkle {
                    0%, 100% { opacity: 0.3; }
                    50% { opacity: 1; }
                }

                .container {
                    position: relative;
                    z-index: 1;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 2rem;
                }

                .header {
                    text-align: center;
                    margin-bottom: 3rem;
                    animation: glow 2s ease-in-out infinite alternate;
                }

                @keyframes glow {
                    from { text-shadow: 0 0 10px #64ffda, 0 0 20px #64ffda, 0 0 30px #64ffda; }
                    to { text-shadow: 0 0 5px #64ffda, 0 0 10px #64ffda, 0 0 15px #64ffda; }
                }

                .header h1 {
                    font-size: 4rem;
                    background: linear-gradient(45deg, #64ffda, #bb86fc, #cf6679);
                    -webkit-background-clip: text;
                    -webkit-text-fill-color: transparent;
                    background-clip: text;
                    margin-bottom: 0.5rem;
                    letter-spacing: 2px;
                }

                .header .subtitle {
                    font-size: 1.2rem;
                    color: #64ffda;
                    opacity: 0.8;
                    margin-bottom: 1rem;
                }

                .year {
                    display: inline-block;
                    padding: 0.5rem 1rem;
                    background: rgba(100, 255, 218, 0.1);
                    border: 1px solid #64ffda;
                    border-radius: 25px;
                    font-size: 0.9rem;
                    color: #64ffda;
                }

                .story-section {
                    background: rgba(26, 26, 46, 0.8);
                    border: 1px solid rgba(100, 255, 218, 0.3);
                    border-radius: 15px;
                    padding: 2rem;
                    margin-bottom: 2rem;
                    backdrop-filter: blur(10px);
                    position: relative;
                    overflow: hidden;
                    transition: all 0.3s ease;
                }

                .story-section:hover {
                    border-color: #64ffda;
                    box-shadow: 0 0 30px rgba(100, 255, 218, 0.2);
                    transform: translateY(-2px);
                }

                .story-section::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: -100%;
                    width: 100%;
                    height: 100%;
                    background: linear-gradient(90deg, transparent, rgba(100, 255, 218, 0.1), transparent);
                    animation: shimmer 3s infinite;
                }

                @keyframes shimmer {
                    0% { left: -100%; }
                    100% { left: 100%; }
                }

                .story-title {
                    font-size: 1.8rem;
                    color: #bb86fc;
                    margin-bottom: 1rem;
                    display: flex;
                    align-items: center;
                    gap: 0.5rem;
                }

                .story-content {
                    line-height: 1.8;
                    color: #e0e6ed;
                    margin-bottom: 1.5rem;
                }

                .story-content em {
                    color: #64ffda;
                    font-style: normal;
                }

                .api-section {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 2rem;
                    margin-top: 3rem;
                }

                .api-card {
                    background: linear-gradient(135deg, rgba(26, 26, 46, 0.9), rgba(22, 33, 62, 0.9));
                    border: 1px solid rgba(187, 134, 252, 0.3);
                    border-radius: 12px;
                    padding: 2rem;
                    text-align: center;
                    transition: all 0.3s ease;
                    position: relative;
                    overflow: hidden;
                }

                .api-card:hover {
                    border-color: #bb86fc;
                    box-shadow: 0 10px 40px rgba(187, 134, 252, 0.3);
                    transform: translateY(-5px) scale(1.02);
                }

                .api-card::after {
                    content: '';
                    position: absolute;
                    top: 50%;
                    left: 50%;
                    width: 0;
                    height: 0;
                    background: radial-gradient(circle, rgba(187, 134, 252, 0.1) 0%, transparent 70%);
                    transition: all 0.6s ease;
                    transform: translate(-50%, -50%);
                }

                .api-card:hover::after {
                    width: 300px;
                    height: 300px;
                }

                .api-card h3 {
                    font-size: 1.5rem;
                    color: #bb86fc;
                    margin-bottom: 1rem;
                    position: relative;
                    z-index: 1;
                }

                .api-card p {
                    color: #e0e6ed;
                    margin-bottom: 1.5rem;
                    opacity: 0.9;
                    position: relative;
                    z-index: 1;
                }

                .api-link {
                    display: inline-block;
                    padding: 0.75rem 1.5rem;
                    background: linear-gradient(45deg, #64ffda, #bb86fc);
                    color: #0f0f23;
                    text-decoration: none;
                    border-radius: 25px;
                    font-weight: bold;
                    transition: all 0.3s ease;
                    position: relative;
                    z-index: 1;
                    overflow: hidden;
                }

                .api-link:hover {
                    transform: scale(1.05);
                    box-shadow: 0 5px 20px rgba(100, 255, 218, 0.4);
                }

                .api-link::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: -100%;
                    width: 100%;
                    height: 100%;
                    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
                    transition: left 0.5s;
                }

                .api-link:hover::before {
                    left: 100%;
                }

                .custodians {
                    margin-top: 3rem;
                    text-align: center;
                }

                .custodians h2 {
                    font-size: 2rem;
                    color: #cf6679;
                    margin-bottom: 2rem;
                }

                .custodian-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 1rem;
                    margin-top: 2rem;
                }

                .custodian {
                    background: rgba(207, 102, 121, 0.1);
                    border: 1px solid rgba(207, 102, 121, 0.3);
                    border-radius: 10px;
                    padding: 1rem;
                    transition: all 0.3s ease;
                }

                .custodian:hover {
                    border-color: #cf6679;
                    box-shadow: 0 5px 20px rgba(207, 102, 121, 0.2);
                }

                .footer {
                    text-align: center;
                    margin-top: 4rem;
                    padding: 2rem;
                    border-top: 1px solid rgba(100, 255, 218, 0.3);
                    color: #64ffda;
                    opacity: 0.8;
                }

                .protocol-bearer {
                    font-style: italic;
                    color: #bb86fc;
                    margin-top: 1rem;
                }

                @media (max-width: 768px) {
                    .header h1 {
                        font-size: 2.5rem;
                    }
                    
                    .container {
                        padding: 1rem;
                    }
                    
                    .api-section {
                        grid-template-columns: 1fr;
                    }
                }

                .pulse {
                    animation: pulse 2s infinite;
                }

                @keyframes pulse {
                    0% { opacity: 1; }
                    50% { opacity: 0.5; }
                    100% { opacity: 1; }
                }
            </style>
        </head>
        <body>
            <div class="stars" id="stars"></div>
            
            <div class="container">
                <header class="header">
                    <h1>🌍 FINABLE</h1>
                    <p class="subtitle">The Protocol Backend - A System Reborn</p>
                    <div class="year">Year 4011 - The Trials Await</div>
                </header>

                <section class="story-section">
                    <h2 class="story-title">🛸 The Story</h2>
                    <div class="story-content">
                        In 2095, the financial world collapsed — not from war but from <em>carelessness</em>.<br><br>
                        
                        Decades of unchecked code, brittle systems, and silent breaches brought the global infrastructure to its knees. 
                        Accounts vanished. Networks froze. Systems hung up. Trust dissolved like data slipping into the void.<br><br>
                        
                        At the centre of it all stood <em>Unoka the Compiler</em> — once hailed as the Architect of Progress — who betrayed the sacred laws of clarity and security.<br><br>
                        
                        Only one stood against the tide: <em>Amarogba, the Last Codebender</em>, who foresaw the collapse and left behind the keys to build anew.<br><br>
                        
                        Now, in the year 4011, the <em>Learnable Guild</em> has uncovered his legacy: <strong>The Protocol</strong>.
                    </div>
                </section>

                <section class="story-section">
                    <h2 class="story-title">🔥 Your Mission</h2>
                    <div class="story-content">
                        The Learnable Guild awaits your code. Each trial passed restores a piece of the Protocol.<br><br>
                        
                        When your vaults seal correctly, your card tokens comply, and your API sings with clarity — 
                        You will awaken what Amarogba left behind: <em>A system reborn. A standard redefined.</em><br><br>
                        
                        <strong>Will you rise as the next architect?</strong>
                    </div>
                </section>

                <section class="api-section">
                    <div class="api-card">
                        <h3>📚 API Documentation</h3>
                        <p>Explore the complete API endpoints and test the Trials of Revival. Study the Protocol and understand each Custodian's challenge.</p>
                        <a href="{{POSTMAN_DOC_LINK}}" class="api-link" target="_blank">View Postman Docs</a>
                    </div>

                    <div class="api-card">
                        <h3>⚡ Source Code</h3>
                        <p>Dive into the codebase and witness the implementation of Amarogba's wisdom. Contribute to the Protocol's evolution.</p>
                        <a href="{{GITHUB_LINK}}" class="api-link" target="_blank">Explore on GitHub</a>
                    </div>
                </section>

                <section class="custodians">
                    <h2>🔥 The Custodians</h2>
                    <p style="color: #64ffda; margin-bottom: 1rem;">The Voices of Lost Systems Who Guide Your Trials</p>
                    
                    <div class="custodian-grid">
                        <div class="custodian">
                            <strong>🧬 Amarogba</strong><br>
                            The Last Codebender
                        </div>
                        <div class="custodian">
                            <strong>⚖️ Obade</strong><br>
                            The Keymaster of Order
                        </div>
                        <div class="custodian">
                            <strong>✨ Adaeze</strong><br>
                            Daughter of Protocols
                        </div>
                        <div class="custodian">
                            <strong>🛡️ Iyanda</strong><br>
                            Of the FireVault
                        </div>
                        <div class="custodian">
                            <strong>🌿 Zubairu</strong><br>
                            Of the Deep Hash
                        </div>
                        <div class="custodian">
                            <strong>📖 Edeba</strong><br>
                            Weaver of Clarity
                        </div>
                        <div class="custodian">
                            <strong>💀 Unoka</strong><br>
                            The Compiler (Warning)
                        </div>
                    </div>
                </section>

                <footer class="footer">
                    <div class="pulse">May the Protocol light your path. May the Light guide you.</div>
                    <div class="protocol-bearer">
                        "The Protocol Bearer walks with you through the Trials.<br>
                        He does not test you — he speaks for those who do."
                    </div>
                </footer>
            </div>

            <script>
                // Generate animated stars
                function createStars() {
                    const starsContainer = document.getElementById('stars');
                    const starCount = 100;
                    
                    for (let i = 0; i < starCount; i++) {
                        const star = document.createElement('div');
                        star.className = 'star';
                        star.style.left = Math.random() * 100 + '%';
                        star.style.top = Math.random() * 100 + '%';
                        star.style.animationDelay = Math.random() * 3 + 's';
                        starsContainer.appendChild(star);
                    }
                }

                // Smooth scrolling for internal links
                document.addEventListener('DOMContentLoaded', function() {
                    createStars();
                    
                    // Add subtle floating animation to story sections
                    const sections = document.querySelectorAll('.story-section');
                    sections.forEach((section, index) => {
                        section.style.animationDelay = (index * 0.2) + 's';
                    });
                });

                // Template variable replacement helper (for server-side rendering)
                function replaceTemplateVars(postmanLink, githubLink) {
                    document.body.innerHTML = document.body.innerHTML
                        .replace(/\{\{POSTMAN_DOC_LINK\}\}/g, postmanLink || '#')
                        .replace(/\{\{GITHUB_LINK\}\}/g, githubLink || '#');
                }

                // Particle effect on hover
                document.addEventListener('mousemove', function(e) {
                    if (Math.random() > 0.95) {
                        const particle = document.createElement('div');
                        particle.style.position = 'fixed';
                        particle.style.left = e.clientX + 'px';
                        particle.style.top = e.clientY + 'px';
                        particle.style.width = '2px';
                        particle.style.height = '2px';
                        particle.style.background = '#64ffda';
                        particle.style.borderRadius = '50%';
                        particle.style.pointerEvents = 'none';
                        particle.style.zIndex = '999';
                        particle.style.animation = 'twinkle 1s ease-out forwards';
                        
                        document.body.appendChild(particle);
                        
                        setTimeout(() => {
                            particle.remove();
                        }, 1000);
                    }
                });
            </script>
        </body>
        </html>
    `;


export default homepageTemplate;