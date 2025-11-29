# 🧩 Lab Guide: Recon & Flag Capture on http://target.ine.local

**Goal:** Perform reconnaissance and capture 5 flags hidden around the webroot and mirrored files.

> **⚠️ Legal / Safety Note:** Only run these steps against lab targets you own or have explicit permission to test (like `target.ine.local`, `zonetransfer.me`, etc.). Do not run intrusive scans against systems you don't own.

---

## 📋 Prerequisites
Ensure you have the following installed in your Kali VM:
* **Tools:** `curl`, `wget`, `httrack`, `gobuster`, `whatweb`, `wafw00f`, `strings`.
* **Browser:** Firefox or Chrome (for viewing directory listings).
* **Access:** Terminal with root/sudo permissions.

---

##  Flag 1 — robots.txt

### Why?
`robots.txt` is a public file sites use to tell search engines which paths *not* to crawl. It often reveals interesting hidden paths (e.g., `/admin`, `/backup`).

### Steps
1.  **Fetch the file:**
    ```bash
    curl -s [http://target.ine.local/robots.txt](http://target.ine.local/robots.txt)
    ```
    *Or visit `http://target.ine.local/robots.txt` in your browser.*

### What to look for
Look for lines beginning with `Disallow`.
```text
User-agent: *
Disallow: /admin/
Disallow: /secret/
```

**The Flag:** The text inside this file is the flag (or contains it).

---

##  Flag 2 — Identify Website & Version

### Why?
The exam requires identifying the running web server, CMS, and their specific versions (e.g., Apache/2.4.41 or WordPress 6.x).

### Steps

1.  **Fastest method (Header check):**
    ```bash
    curl -I [http://target.ine.local](http://target.ine.local)
    ```
    Look for `Server:` or `X-Powered-By:` headers.

2.  **Detailed Fingerprint:**
    ```bash
    whatweb [http://target.ine.local](http://target.ine.local)
    # Or for verbose output:
    whatweb -v [http://target.ine.local](http://target.ine.local)
    ```

### What to extract
You are looking for specific version numbers.

* **Example:** `Server: Apache/2.4.41 (Ubuntu)`
* **Example:** `WordPress 6.2.0`

**The Flag:** The specific server name and version string.

---

##  Flag 3 — Directory Listing (Uploads)

### Why?
If a server has "Directory Listing" enabled, anyone can see a list of files in a folder. Labs commonly hide flags in the `/wp-content/uploads/` directory.

### Steps

1.  **Scan for directories:**
    ```bash
    gobuster dir -u [http://target.ine.local](http://target.ine.local) -w /usr/share/wordlists/dirb/common.txt
    ```

2.  **Analyze Output:**
    Look for status code `301` (Redirect) or `200` (OK) on folders like:
    * `/wp-content`
    * `/wp-includes`
    * `/uploads`

3.  **Browse the directory:**
    Visit: `http://target.ine.local/wp-content/uploads/`

### What to look for
If you see an **"Index of /"** page, click through the files. Look for:
* `flag3.txt`
* `hidden.txt`
* Suspicious images.

**The Flag:** The content found inside the file located in the uploads directory.

---

##  Flag 4 — Backup Files (wp-config.bak)

### Why?
Administrators sometimes edit configuration files and leave backup copies (ending in `.bak`, `.old`, `.save`) in the webroot. These often contain database credentials or flags.

### Steps

1.  **Scan for specific file extensions:**
    ```bash
    gobuster dir -u [http://target.ine.local](http://target.ine.local) -w /usr/share/wordlists/dirb/common.txt -x bak,old,zip,tar.gz
    ```

2.  **Identify the file:**
    Look for a `200` status code on:
    * `/wp-config.bak`

3.  **Download and Inspect:**
    ```bash
    curl -s [http://target.ine.local/wp-config.bak](http://target.ine.local/wp-config.bak) -o wp-config.bak
    cat wp-config.bak
    ```

### What to look for
Read the file content for comments or defined constants.

```php
// FLAG4{this_is_flag_4}
define('DB_USER', 'wpuser');
```
**The Flag:** The specific string hidden inside the backup config file.

---

## Flag 5 — Hidden Files via Mirroring (HTTrack)

### Why?
Some files exist on the server but are not linked on the main homepage (orphaned files). `HTTrack` is excellent at finding these by aggressively spidering the site.

### Steps

1.  **Mirror the site:**
    ```bash
    httrack "[http://target.ine.local](http://target.ine.local)" -O ~/target_mirror -v
    ```
    This downloads the site to `~/target_mirror/target.ine.local/`.

2.  **Scan the downloaded files:**
    Navigate to the directory and list files:
    ```bash
    cd ~/target_mirror/target.ine.local
    find . -type f
    grep -R --line-number -i "flag" .
    ```
> This was a tedious work to search for but finally it paid off

### What to look for
Look for files with suspicious names or extensions that don't match their location:
* `index905b.html`
* `wp-login_OLD.html`
* `.../assets/images/tourist.html` (An HTML file inside an images folder is very suspicious).

**The Flag:** Open the suspicious HTML file to find the final flag.

> This was a very tedious job. Even with these pointers there would be a lot stones to skip and a tears to shed. Lol good luck
