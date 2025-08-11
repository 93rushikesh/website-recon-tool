  🔍 Website Recon Tool

A simple yet powerful **information gathering tool** for website reconnaissance.

---

   ✨ Features

- 🔸 **Subdomain Enumeration** – Find related subdomains of a domain.  
- 🔸 **Port Scanning** – Detect open ports (multi-threaded for speed).  
- 🔸 **HTTP Headers Extraction** – View server details & security headers.  
- 🔸 **WHOIS Lookup** – Get domain registration info.  
- 🔸 **IP Address & Geolocation** – Locate the server worldwide.  
- 🔸 **Technology Stack Detection** – Identify hosting & CMS tech.  
- 🔸 **Firewall Detection** – Check if WAF is enabled.  

---

  ⚙️ Installation

```bash
git clone https://github.com/93rushikesh/website-recon-tool.git
cd website-recon-tool

sudo apt install python3-full
python3 -m venv myenv
source myenv/bin/activate

pip install -r requirements.txt
```
  If on Linux And Need Sudo:
```
sudo pip install -r requirements.txt
```
 🚀 Usage
```
python website_recon.py
```
  Example:
```
Enter Domain (e.g. example.com): certifiedhacker.com
```
  🧾 Example Output
✅ Subdomains: Found list of related domains.

🔓 Open Ports: Detected running services.

📥 HTTP Headers: Security & server details.

🧾 WHOIS Info: Owner, email, creation & expiry dates.

🌍 IP Location: Country, city & ISP info.

⚙️ Technology: Hosting provider & tech stack.

🛡️ Firewall: Detected Cloudflare WAF.

  📦 Requirements requests

python-whois

colorama

wafw00f

Install with:
```
pip install -r requirements.txt
```
👨‍💻 Author
Rushikesh Gadekar
```
🐙 GitHub: 93rushikesh

💬 Telegram: @CIPHER_372

📸 Instagram: @_gadekar_rushikesh

🔗 LinkedIn: gadekarrushikesh
```
🙋‍♂️ About Me
I’m a cybersecurity enthusiast 🛡️, ethical hacker 💻, bug bounty hunter 🐞, and cyber investigator 🔍.
I love exploring vulnerabilities, securing systems, and building open-source tools to make the digital world safer.
