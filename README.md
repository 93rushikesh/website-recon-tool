🔍 Website Recon Tool
A simple yet powerful information gathering tool for reconnaissance of websites.

Features:

🔸 Subdomain enumeration – Find related subdomains of a domain.

🔸 Port scanning – Detect open ports (multi-threaded for speed).

🔸 HTTP headers extraction – View server details & security headers.

🔸 WHOIS lookup – Get domain registration info.

🔸 IP address & geolocation – Locate the server worldwide.

🔸 Technology stack detection – Identify hosting & CMS tech.

🔸 Firewall detection – Check if WAF is enabled.

⚙️ Installation
bash
कॉपी करा
बदल करा
git clone https://github.com/93rushikesh/website-recon-tool.git
cd website-recon-tool

sudo apt install python3-full
python3 -m venv myenv
source myenv/bin/activate

pip install -r requirements.txt
If on Linux:

bash
कॉपी करा
बदल करा
sudo pip install -r requirements.txt
🚀 Usage
bash
कॉपी करा
बदल करा
python website_recon.py
Example:

java
कॉपी करा
बदल करा
Enter Domain (e.g. example.com): certifiedhacker.com
🧾 Example Output
✅ Subdomains: Found list of related domains.

🔓 Open Ports: Detected running services.

📥 HTTP Headers: Security & server details.

🧾 WHOIS Info: Owner, email, creation & expiry dates.

🌍 IP Location: Country, city & ISP info.

⚙️ Technology: Hosting provider & tech stack.

🛡️ Firewall: Detected Cloudflare WAF.

📦 Requirements
nginx
कॉपी करा
बदल करा
requests
python-whois
colorama
wafw00f
Install with:

bash
कॉपी करा
बदल करा
pip install -r requirements.txt
👨‍💻 Author
Rushikesh Gadekar

🐙 GitHub: 93rushikesh

💬 Telegram: @CIPHER_372

📸 Instagram: @_gadekar_rushikesh

🔗 LinkedIn: gadekarrushikesh

🙋‍♂️ About Me
I’m a cybersecurity enthusiast 🛡️, ethical hacker 💻, bug bounty hunter 🐞, and cyber investigator 🔍.
I love exploring vulnerabilities, securing systems, and building open-source tools to make the digital world safer.
