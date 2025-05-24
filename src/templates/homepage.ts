const homepageTemplate=`      
        
        <!DOCTYPE html>
            <html lang="en">

            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>{{title}}</title>
                <style>
                    /* Base styling */
                    body {
                        margin: 0;
                        padding: 0;
                        font-family: Arial, Helvetica, sans-serif;
                        color: #333;
                        line-height: 1.5;
                    }

                    /* Email container */
                    .email-container {
                        max-width: 600px;
                        margin: 0 auto;
                        background-color: #ffffff;
                        padding: 20px;
                    }

                    /* Header section */
                    .header {
                        text-align: left;
                        padding-bottom: 10px;
                        border-bottom: 1px solid #eaeaea;
                    }

                    /* Content sections */
                    .content-section {
                        padding: 20px 0;
                    }

                    /* Hero image */
                    .hero-image {
                        width: 100%;
                        max-width: 550px;
                        height: auto;
                        background-color: #f2e6ff;
                        border-radius: 8px;
                        margin: 20px 0;
                    }

                    /* Typography */
                    h1 {
                        color: #333;
                        font-size: 24px;
                        margin-bottom: 15px;
                    }

                    p {
                        margin: 10px 0;
                        font-size: 16px;
                    }

                    /* List styling */
                    ul {
                        padding-left: 20px;
                    }

                    li {
                        margin-bottom: 8px;
                    }

                    /* Button/CTA styling */
                    .cta-section {
                        margin: 25px 0;
                    }

                    .cta-step {
                        margin: 10px 0;
                        font-weight: 500;
                    }

                    /* Footer */
                    .footer {
                        padding-top: 20px;
                        border-top: 1px solid #eaeaea;
                        color: #777;
                        font-size: 14px;
                        font-style: italic;
                    }

                    /* Emoji */
                    .emoji {
                        font-size: 18px;
                    }

                    /* Responsive */
                    @media screen and (max-width: 480px) {
                        .email-container {
                            padding: 10px;
                        }

                        h1 {
                            font-size: 20px;
                        }

                        p,
                        li {
                            font-size: 15px;
                        }
                    }
                </style>
            </head>

            <body>
                <div class="email-container">
                    <!-- Email content -->
                    <div class="content-section">
                        <p>Welcome to {{companyName}}, your new favorite (and sassiest) study buddy. {{welcomeMessage}}</p>

                        <p>{{noPresssureText}}<br>
                            {{excitedText}} <span class="emoji">{{emoji}}</span>.</p>

                        <!-- Hero image -->
                        <img src="https://ik.imagekit.io/5hv70bbh5/Screenshot%202025-05-11%20002957.png?updatedAt=1746919860150"
                            alt="{{heroImageAlt}}" width="600"
                            style="display:block; margin: 0 auto; max-width:100%; height:auto;" />


                        <h1>{{benefitsHeading}}</h1>

                        <ul>
                            {{#each benefits}}
                            <li><strong>{{title}}</strong> {{description}}</li>
                            {{/each}}
                        </ul>

                        <p>{{ctaQuestion}}</p>

                        <div class="cta-section">
                            {{#each ctaSteps}}
                            <p class="cta-step">→ {{this}}</p>
                            {{/each}}
                        </div>

                        <p>{{callToAction}}</p>
                    </div>

                    <!-- Footer -->
                    <div class="footer">
                        <p>- {{teamSignature}}</p>
                        <p>({{tagline}})</p>
                    </div>
                </div>
            </body>

            </html>
    `;


export default homepageTemplate;