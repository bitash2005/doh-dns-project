function setMsg(text) {
    document.getElementById("msg").innerText = text || "";
  }
  
  function getAuthHeader() {
    const u = localStorage.getItem("admin_user") || "";
    const p = localStorage.getItem("admin_pass") || "";
    const token = btoa(`${u}:${p}`);
    return { "Authorization": `Basic ${token}` };
  }
  
  async function fetchRecords() {
    setMsg("در حال دریافت رکوردها...");
    const res = await fetch("/admin/records", { headers: { ...getAuthHeader() } });
  
    if (!res.ok) {
      setMsg("خطا در دریافت رکوردها (احتمالاً یوزر/پس اشتباه است).");
      return;
    }
  
    const data = await res.json();
    renderTable(data.items || []);
    setMsg("OK");
  }
  
  function renderTable(items) {
    const tbody = document.getElementById("tbody");
    tbody.innerHTML = "";
  
    for (const r of items) {
      const tr = document.createElement("tr");
  
      const tdDomain = document.createElement("td");
      tdDomain.innerText = r.domain;
  
      const tdType = document.createElement("td");
      tdType.innerText = r.type;
  
      const tdValue = document.createElement("td");
      tdValue.innerText = r.value;
  
      const tdTTL = document.createElement("td");
      tdTTL.innerText = r.ttl;
  
      const tdPri = document.createElement("td");
      tdPri.innerText = (r.priority === null || r.priority === undefined) ? "" : r.priority;
  
      const tdAct = document.createElement("td");
      const btn = document.createElement("button");
      btn.innerText = "Delete";
      btn.onclick = async () => {
        if (!confirm(`حذف رکوردهای دامنه ${r.domain} ؟`)) return;
        await deleteDomain(r.domain);
        await fetchRecords();
      };
      tdAct.appendChild(btn);
  
      tr.appendChild(tdDomain);
      tr.appendChild(tdType);
      tr.appendChild(tdValue);
      tr.appendChild(tdTTL);
      tr.appendChild(tdPri);
      tr.appendChild(tdAct);
  
      tbody.appendChild(tr);
    }
  }
  
  async function addRecord() {
    const domain = document.getElementById("domain").value.trim();
    const type = document.getElementById("rtype").value.trim();
    const value = document.getElementById("value").value.trim();
    const ttl = parseInt(document.getElementById("ttl").value, 10);
    const priority = parseInt(document.getElementById("priority").value, 10);
  
    if (!domain || !type || !value) {
      setMsg("domain/type/value نباید خالی باشد.");
      return;
    }
    if (Number.isNaN(ttl) || ttl <= 0) {
      setMsg("TTL باید عدد مثبت باشد.");
      return;
    }
    if (type === "MX" && (Number.isNaN(priority) || priority < 0)) {
      setMsg("Priority برای MX باید عدد معتبر باشد.");
      return;
    }
  
    const payload = { domain, type, value, ttl, priority };
  
    setMsg("در حال افزودن...");
    const res = await fetch("/admin/record", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...getAuthHeader()
      },
      body: JSON.stringify(payload)
    });
  
    if (!res.ok) {
      const t = await res.text();
      setMsg("خطا در افزودن رکورد: " + t);
      return;
    }
  
    setMsg("رکورد اضافه شد.");
  }
  
  async function deleteDomain(domain) {
    setMsg("در حال حذف...");
    const res = await fetch(`/admin/record/${encodeURIComponent(domain)}`, {
      method: "DELETE",
      headers: { ...getAuthHeader() }
    });
  
    if (!res.ok) {
      const t = await res.text();
      setMsg("خطا در حذف رکورد: " + t);
      return;
    }
    setMsg("حذف شد.");
  }
  
  document.getElementById("saveCreds").onclick = () => {
    localStorage.setItem("admin_user", document.getElementById("user").value);
    localStorage.setItem("admin_pass", document.getElementById("pass").value);
    setMsg("Credentials ذخیره شد.");
  };
  
  document.getElementById("refreshBtn").onclick = fetchRecords;
  
  document.getElementById("addBtn").onclick = async () => {
    await addRecord();
    await fetchRecords();
  };
  
  fetchRecords();
  