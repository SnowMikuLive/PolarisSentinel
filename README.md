# PolarisSentinel

Polaris Sentinel Project aims to create a prototype that automatically detects and response to network threats using AI.

The system continuously monitors network traffic, extracts relevant features and applies a pretrained AI model to determine whether the traffic is benign or malicious. 
The inference results are then passed to a policy decision engine governed by administrator defined rules to decide if source IP address or port should be blocked. Administrators can view real-time network traffic and AI-generated results, configure policies, and manage rules through web dashboard management console. 

The goal is to allow the AI continually to reinforce the organization’s security posture while keeping humans in the loop. 

The architecture follows a detection, decision, response and enforcement model. Given the constraints of a capstone timeline. 

The prototype narrows its focus to inbound traffic and targets three of the most common and high impact attack types observed in this traffic: Denial-of-Service (DoS), port scanning, and brute-force login attempts on Windows-based environment
