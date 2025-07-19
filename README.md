🔍 Website Recon Tool
A simple and effective information gathering tool for reconnaissance of websites.

This tool performs:

🔸 Subdomain enumeration (Coming Soon)

🔸 Port scanning (ports 80, 443)

🔸 HTTP headers extraction

🔸 WHOIS lookup

🔸 IP address & geolocation

🔸 Technology stack detection

🔸 Basic firewall detection (via server headers)

⚙️ Installation
Clone the repository and install dependencies:

git clone https://github.com/93rushikesh/website-recon-tool.git
cd website-recon-tool
pip install -r requirements.txt

(For Linux users with sudo):

sudo pip install -r requirements.txt

🚀 Usage
Run the tool:

python website_recon.py

Then enter the target domain:

Enter Domain (e.g. example.com): google.com

🧾 Output Example
✅ Subdomain suggestions

🔓 Open ports (80, 443)

📥 HTTP response headers

🧾 WHOIS info (registrant, emails, etc.)

🌍 IP address and location

⚙️ Technology detection (Cloudflare, Google Server, etc.)

🛡️ Firewall clues (based on headers)

📦 Requirements
requests

python-whois

Installed via:

pip install -r requirements.txt

👨‍💻 Author
Rushikesh Gadekar
GitHub: https://github.com/93rushikesh
