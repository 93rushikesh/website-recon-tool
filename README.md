🕵️‍♂️ Website Recon Tool:
  description: "A powerful & advanced information gathering tool for professional website reconnaissance."

✨ Features:
  - 🌐 Subdomain Enumeration: "Discover hidden & related subdomains."
  - 🚪 Port Scanning: "Identify open ports & services (multi-threaded for speed)."
  - 📜 HTTP Headers Extraction: "Reveal server, framework & security headers."
  - 🔍 WHOIS Lookup: "Domain owner details, emails, creation & expiry."
  - 📡 IP Address & Geolocation: "Pinpoint server’s global location."
  - 🛠 Technology Stack Detection: "Detect hosting provider, CMS, frameworks."
  - 🛡 Firewall Detection: "Identify WAFs like Cloudflare."

⚙️ Installation:
  - command: |
      git clone https://github.com/93rushikesh/website-recon-tool.git
      cd website-recon-tool
      sudo apt install python3-full
      python3 -m venv myenv
      source myenv/bin/activate
      pip install -r requirements.txt
  - linux_sudo_install: |
      sudo pip install -r requirements.txt

🚀 Usage:
  - command: |
      python website_recon.py
  - example:
      input: "Enter Domain (e.g. example.com): certifiedhacker.com"
      output:
        - "✅ Subdomains → Found related domains."
        - "🔓 Open Ports → Services & running applications detected."
        - "📥 HTTP Headers → Server & security insights."
        - "🧾 WHOIS Info → Owner, email, creation & expiry dates."
        - "🌍 IP Location → Country, city, ISP."
        - "⚙️ Technology → Hosting, CMS, frameworks."
        - "🛡 Firewall → Cloudflare WAF detected."

📦 Requirements:
  - requests
  - python-whois
  - colorama
  - wafw00f
  - install_command: "pip install -r requirements.txt"

  ## 👨‍💻 Author
**Name:** Rushikesh Gadekar  

- 🐙 **GitHub:** [93rushikesh](https://github.com/93rushikesh)  
- 📢 **Telegram:** [@CIPHER_372](https://t.me/CIPHER_372)  
- 📸 **Instagram:** [@_gadekar_rushikesh](https://instagram.com/_gadekar_rushikesh)  
- 💼 **LinkedIn:** [gadekarrushikesh](https://linkedin.com/in/gadekarrushikesh)
- Bio: "Cybersecurity Enthusiast 🛡️ | Ethical Hacker 💻 | Bug Bounty Hunter 🐞 | Cyber Investigator 🔍"
