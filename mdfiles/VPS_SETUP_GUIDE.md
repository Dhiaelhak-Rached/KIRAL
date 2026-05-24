# VPS Setup Guide — Stop Losing Internet During Scans

> **What this guide does:** It walks you through moving the "scanning" part of your pipeline to a cloud computer (VPS) so your home Wi-Fi stops crashing. You will still keep your database (ClickHouse + Redis) on your local server at home. We use free tools to connect everything securely.

---

## The Problem (In Simple Words)

When your laptop runs **Stage 3 (Port Scanning)**, it sends thousands of connection requests across the internet. Three things happen at once:

1. **Your Wi-Fi adapter panics** and resets itself.
2. **Your home router thinks it's under attack** and cuts your internet for 30–60 seconds.
3. **Your ISP may see the flood** and temporarily block you.

Even after we made the scanner "stealthier," your home network hardware is simply not built for this kind of traffic.

## The Solution (In Simple Words)

We rent a cheap **cloud computer** (called a VPS) and tell it to do the scanning instead. This computer lives in a data center with business-grade internet — it never disconnects.

Because your database (ClickHouse + Redis) still lives on your home server, we build a **secure private tunnel** between the cloud computer and your home. This tunnel is invisible to the internet and works even if your home IP address changes.

Finally, because you are still building and changing code every day, we set up **VS Code Remote-SSH**. This lets you write code on your laptop (with your familiar editor) but the files actually live on the cloud computer. When you press Save, you are saving to the cloud. When you press Run, it runs on the cloud.

---

## What You Need Before Starting

- A credit card or PayPal account (for the VPS, ~$5/month).
- About 30 minutes.
- Your local server (the machine with ClickHouse + Redis) turned on.

---

## Step 1: Rent a VPS (Cloud Computer)

A **VPS** is just a small Linux computer you rent by the month. You never see it physically — you control it over the internet.

### Recommended Providers

| Provider | Cheapest Plan | Location | Why |
|----------|--------------|----------|-----|
| **Hetzner** | ~€4.51/month | Germany / Finland | Best price, fast |
| **DigitalOcean** | $6/month | Many | Very beginner-friendly |
| **Vultr** | $5/month | Many | Simple control panel |
| **Linode (Akamai)** | $5/month | Many | Good documentation |

### What to Choose When Signing Up

- **Operating System:** `Ubuntu 24.04 LTS`
- **Plan / Size:** The cheapest one (1 vCPU, 1–2 GB RAM, 20 GB SSD).
- **Location:** Pick the city closest to you for lower latency.
- **Authentication:** Choose **SSH Key** if you know how. Otherwise choose **Password** for now.

After you pay, the provider will give you an **IP address** that looks like `203.0.113.45`. Write it down. We will call this `YOUR_VPS_IP` in the rest of this guide.

> **Why this fixes the disconnect:** The VPS sits in a data center. Its network card is designed for heavy traffic. Its router does not have "consumer flood protection." Its ISP expects servers to send lots of packets.

---

## Step 2: Log Into Your VPS for the First Time

You need a program called an **SSH client** to talk to your VPS.

### On Windows

Use **PowerShell** or **Git Bash** (which you already have). Run:

```bash
ssh root@YOUR_VPS_IP
```

If you chose password authentication, type the password the provider emailed you.

If you see a scary warning about "host authenticity," type `yes` and press Enter. This is normal.

Once you are in, your prompt will look something like:

```bash
root@ubuntu-2gb-hel1-1:~#
```

This means you are now controlling the cloud computer.

---

## Step 3: Create a Normal User (Don't Use `root`)

Running everything as `root` is dangerous. Create a normal user for yourself.

Run these commands **on the VPS**:

```bash
# Create user "rache" (change to any name you want)
adduser rache

# Give this user permission to use "sudo" (admin rights)
usermod -aG sudo rache
```

It will ask you to set a password and some optional info. Just set the password.

Now log out of root and log in as your new user:

```bash
exit
ssh rache@YOUR_VPS_IP
```

> **Why:** If you make a typo while running as `root`, you can accidentally delete the entire operating system. A normal user prevents that.

---

## Step 4: Install Tailscale (The Secret Tunnel)

**Tailscale** is free software that creates a private network between your devices. Think of it like a VPN, but automatic and secure. After this step, your VPS will be able to talk to your home server as if they were in the same room.

### Install on the VPS

Run this **on the VPS**:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

It will print a link like `https://login.tailscale.com/a/abc123`. Open that link in your laptop's browser and sign in with a Google, Microsoft, or GitHub account.

### Install on Your Local Server

Open a terminal on your **local server** (the machine at `192.168.1.21` that runs ClickHouse + Redis) and run the exact same commands:

```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
```

Sign in with the **same account**.

### Check That It Worked

On your **local server**, run:

```bash
tailscale ip -4
```

It will print an IP that looks like `100.x.x.x`. For example:

```
100.64.23.45
```

Write this down. We will call it `YOUR_TAILSCALE_IP`.

Now on your **VPS**, test if you can reach your home server through the tunnel:

```bash
ping YOUR_TAILSCALE_IP
```

If you see replies, the tunnel is working.

> **Why Tailscale:** Normally your home router blocks the outside world from reaching `192.168.1.21`. Tailscale punches through your router automatically without you touching any settings. It also encrypts everything.

---

## Step 5: Install the Project on the VPS

Now we put your code on the cloud computer.

### Install Required Software

Run these **on the VPS**:

```bash
# Update the system
sudo apt update && sudo apt upgrade -y

# Install Python, Git, and other basics
sudo apt install -y python3-venv python3-pip git curl

# Install RustScan (the port scanner)
# Method 1: If available in apt
sudo apt install rustscan

# Method 2: If apt doesn't have it, download the binary
curl -sSL https://github.com/RustScan/RustScan/releases/download/2.4.1/rustscan_2.4.1_amd64.deb -o rustscan.deb
sudo dpkg -i rustscan.deb
```

### Clone Your Repository

```bash
# Go to your home folder
cd ~

# Clone your project (use your real Git URL)
git clone https://github.com/Dhiaelhak-Rached/KIRAL.git

# Enter the project folder
cd KIRAL

# Create a Python virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install Python packages
pip install -r requirements.txt
```

> **Why a virtual environment:** This keeps the project's Python packages separate from the system. No conflicts.

---

## Step 6: Update the `.env` File on the VPS

Your project has a file called `.env` that tells the code where Redis and ClickHouse live.

Right now it probably says:

```bash
ASM_REDIS_HOST=192.168.1.21
ASM_CH_URL=http://192.168.1.21:8123/
```

**On the VPS**, open `.env` and change those lines to use your **Tailscale IP**:

```bash
nano .env
```

Change them to:

```bash
ASM_REDIS_HOST=YOUR_TAILSCALE_IP
ASM_CH_URL=http://YOUR_TAILSCALE_IP:8123/
```

For example:

```bash
ASM_REDIS_HOST=100.64.23.45
ASM_CH_URL=http://100.64.23.45:8123/
```

Save the file (in nano: press `Ctrl+O`, then `Enter`, then `Ctrl+X`).

> **Why:** `192.168.1.21` only works inside your house. The VPS is on the internet. The Tailscale IP (`100.x.x.x`) works from anywhere because it travels through the encrypted tunnel.

---

## Step 7: Tell Docker to Accept Tailscale Visitors

Here is the most important fix that is easy to miss.

Your Redis and ClickHouse are running **inside Docker containers** on your local server. Right now, your `docker-compose.yml` only opens the door for visitors arriving at `192.168.1.21` (your home LAN). It looks like this:

```yaml
ports:
  - "192.168.1.21:6379:6379"
```

But your VPS will arrive via the **Tailscale tunnel** at `100.x.x.x`. Docker sees a visitor at the Tailscale door and says, *"Nope, not my problem."*

### The Fix

On your **local server**, open `docker-compose.yml`:

```bash
cd ~/KIRAL   # or wherever your project lives
nano docker-compose.yml
```

Find these two sections and change them:

**Redis:**
```yaml
# OLD
    ports:
      - "192.168.1.21:6379:6379"

# NEW
    ports:
      - "0.0.0.0:6379:6379"
```

**ClickHouse:**
```yaml
# OLD
    ports:
      - "192.168.1.21:8123:8123"
      - "192.168.1.21:9000:9000"

# NEW
    ports:
      - "0.0.0.0:8123:8123"
      - "0.0.0.0:9000:9000"
```

Save the file (`Ctrl+O`, `Enter`, `Ctrl+X`).

Then restart the containers:

```bash
docker compose down
docker compose up -d
```

> **Why `0.0.0.0`?** This means "listen on ALL network interfaces" — your home LAN (`192.168.1.21`) **and** your Tailscale tunnel (`100.x.x.x`).
>
> **Is this safe?** Yes, because:
> 1. Your home router's NAT still blocks random internet strangers.
> 2. Tailscale encrypts everything and only allows devices in your account.
> 3. Redis requires the password `changeme`.
> 4. ClickHouse requires the `asm_ingestor` username and password.

### Test the Connection

Now on your **VPS**, test if it can reach your home server through the tunnel.

**Test Redis:**

```bash
# Install redis-cli if you don't have it
sudo apt install -y redis-tools

# Test connection (use your real password)
redis-cli -h YOUR_TAILSCALE_IP -a changeme ping
```

If it replies `PONG`, Redis is reachable.

**Test ClickHouse:**

```bash
curl "http://asm_ingestor:changeme@YOUR_TAILSCALE_IP:8123/?query=SELECT%201"
```

If it replies `1`, ClickHouse is reachable.

If either test fails, check:
1. Is Tailscale running on both machines? (`sudo tailscale status`)
2. Did you restart Docker after changing `docker-compose.yml`? (`docker compose ps`)
3. Is your local server's firewall blocking port 6379 / 8123 on the Tailscale interface? (`sudo ufw status`)

---

## Step 8: Set Up VS Code Remote-SSH (Edit Code from Your Laptop)

You don't want to use `nano` or `vim` to write code. You want your normal VS Code with autocompletion, syntax highlighting, and your themes.

**VS Code Remote-SSH** lets your laptop be the "screen and keyboard" while the files and programs live on the VPS.

### Install the Extension

1. On your **laptop**, open VS Code.
2. Go to the Extensions sidebar (`Ctrl+Shift+X`).
3. Search for **Remote - SSH** by Microsoft.
4. Click **Install**.

### Connect to the VPS

1. Press `F1` (or `Ctrl+Shift+P`) to open the Command Palette.
2. Type `Remote-SSH: Connect to Host...` and click it.
3. Click `+ Add New SSH Host`.
4. Type: `ssh rache@YOUR_VPS_IP`
5. Press Enter, then select the first config file it offers (usually `C:\Users\rache\.ssh\config`).
6. A new VS Code window opens. In the bottom-left corner, you will see a green box saying `SSH: YOUR_VPS_IP`.
7. Click **Open Folder** and select `~/KIRAL` (or `/home/rache/KIRAL`).

### What You Will See

- The file explorer on the left shows the files that live on the VPS.
- When you open `src/orchestrator.py`, you are editing the **VPS copy**.
- When you press `Ctrl+S`, it saves to the VPS instantly.
- When you open a terminal (`Ctrl+`` `), it runs commands **on the VPS**.
- When you run `python -m src.orchestrator example.com`, it runs **on the VPS**.

> **Why this is magic:** You get the comfort of your laptop (big screen, your fonts, your shortcuts) but the heavy work happens on the cloud computer. No file syncing needed. No "uploading" code. It just works.

---

## Step 9: Run Your First Scan from the VPS

Everything is connected. Let's test it.

In the VS Code terminal (which is running on the VPS), make sure you are in the project folder and the virtual environment is active:

```bash
cd ~/KIRAL
source venv/bin/activate
```

Now run a scan against a domain you own or have permission to test:

```bash
python -m src.orchestrator scanme.nmap.org
```

Watch the output. You should see:
- Stage 1: Subdomain enumeration
- Stage 2: DNS resolution
- Stage 3: Port scanning (this is the one that used to disconnect you!)
- Stage 4: HTTP probing

**While it runs, check your laptop's internet.** Browse a website. It should stay connected perfectly because the scan is now happening in the data center, not on your Wi-Fi.

---

## Step 10: What Stays on Your Local Server?

You moved the **scanner** to the VPS. But these stay home:

| Component | Location | Why |
|-----------|----------|-----|
| **Redis** | Local Server | Fast, low-latency queue |
| **ClickHouse** | Local Server | Your permanent database stays home |
| **Consumer** | Local Server | Reads from Redis, writes to ClickHouse. Keeping it next to the database is fastest. |
| **Scanner** | VPS | This is the noisy part that crashes your Wi-Fi |

### Make Sure Your Local Server Is Still Running

On your **local server**, ensure these are active:

```bash
# Check Redis
sudo systemctl status redis

# Check ClickHouse
sudo systemctl status clickhouse-server

# Check Consumer (if you run it as a service)
sudo systemctl status kiral-consumer
```

If the consumer is not a service yet, just run it manually for now:

```bash
cd ~/KIRAL
source venv/bin/activate
python -m src.run_consumer
```

---

## Troubleshooting

### "I can't ping my home server from the VPS"

Run `sudo tailscale status` on **both** machines. You should see both devices listed. If one is missing, run `sudo tailscale up` again.

### "Redis says 'Connection refused' from the VPS"

This means Docker is not letting Tailscale traffic through. On your **local server**:

1. Check `docker-compose.yml` — the port binding should be `0.0.0.0:6379:6379`, not `192.168.1.21:6379:6379`.
2. Run `docker compose ps` — both containers should show `Up`.
3. Check if your local server has a firewall (`sudo ufw status` or `sudo iptables -L`). If yes, allow the Tailscale interface:
   ```bash
   sudo ufw allow in on tailscale0 to any port 6379
   sudo ufw allow in on tailscale0 to any port 8123
   ```

### "ClickHouse says 'Connection refused' from the VPS"

Same as above — check the Docker port binding in `docker-compose.yml`. ClickHouse inside the container already listens on `0.0.0.0` (you can see this in `clickhouse/config.xml`), so Docker is the only gatekeeper.

### "I get 'Permission denied' when SSHing to the VPS"

You probably chose password authentication when creating the VPS. Use:

```bash
ssh root@YOUR_VPS_IP
```

And type the password from your provider's email. Then follow Step 3 to create a normal user.

### "My laptop still disconnects when I run the scan"

You are probably accidentally running it on your laptop instead of the VPS. Check the VS Code bottom-left corner. It should say `SSH: YOUR_VPS_IP`. If it says nothing, you are in a local window.

---

## Summary

| Step | What You Did | Why |
|------|--------------|-----|
| 1 | Rented a VPS | A cloud computer that can handle scanning without crashing |
| 2 | Created a user | Safety — don't run everything as root |
| 3 | Installed Tailscale | Created an encrypted tunnel between VPS and home |
| 4 | Cloned project + installed tools | The scanner now lives in the cloud |
| 5 | Updated `.env` with Tailscale IP | The VPS knows how to reach your home database |
| 6 | Tested Redis and ClickHouse | Confirmed the tunnel works |
| 7 | Set up VS Code Remote-SSH | You can edit cloud files from your laptop |
| 8 | Ran a scan | Your Wi-Fi stayed online! |

**Welcome to server-grade scanning.** Your home network is safe, your code is in the cloud, and your database is still under your desk where you want it.
