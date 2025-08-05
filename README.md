# 🔍 Website Recon Tool

A simple and effective information gathering tool for reconnaissance of websites.

This tool performs:
- 🔸 Subdomain enumeration
- 🔸 Port scanning 
- 🔸 HTTP headers extraction
- 🔸 WHOIS lookup
- 🔸 IP address & geolocation
- 🔸 Technology stack detection
- 🔸 Basic firewall detection

---

## ⚙️ Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/93rushikesh/website-recon-tool.git
cd website-recon-tool
sudo apt install python3-full
python3 -m venv myenv
source myenv/bin/activate
pip install colorama
pip install wafw00f
pip install -r requirements.txt
```
If you're using Linux and need sudo:

```bash
sudo pip install -r requirements.txt
```
## 🚀 Usage
Run the tool:
```bash
python website_recon.py
```
Then enter the target domain:
Enter Domain (e.g. example.com): google.com

## 🧾 Output Example

✅ Subdomains

🔓 Open ports

📥 HTTP response headers

🧾 WHOIS info (registrant, emails, etc.)

🌍 IP address and location

⚙️ Technology detection (Cloudflare, Google Server, etc.)

🛡️ Firewall clues (based on headers)

📦 Requirements
Listed in requirements.txt:
requests
python-whois
Install with:
```bash
pip install -r requirements.txt
```
## 👨‍💻 Author  
Rushikesh Gadekar  
**GitHub:** [https://github.com/93rushikesh](https://github.com/93rushikesh)

## 🙋‍♂️ About Me  
I'm **Rushikesh Gadekar**, a passionate cybersecurity enthusiast 🛡️, ethical hacker 💻, bug bounty hunter 🐞, and a cyber investigator.  
I enjoy diving deep into security systems, finding vulnerabilities, and helping improve digital safety through open-source tools and ethical practices.

## 📫 Contact Me:  
- 🐙 GitHub: [93rushikesh](https://github.com/93rushikesh)  
- 💬 Telegram: [@CIPHER_372](https://t.me/CIPHER_372)  
- 📸 Instagram: [@_gadekar_rushikesh](https://instagram.com/_gadekar_rushikesh)
