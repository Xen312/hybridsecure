// utils.js
export function u8ToBase64Url(u8) {
  const binary = String.fromCharCode(...u8);
  let b64 = btoa(binary);
  b64 = b64.replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
  return b64;
}
export function base64UrlToU8(b64url) {
  let b64 = b64url.replace(/-/g,'+').replace(/_/g,'/');
  const pad = b64.length % 4;
  if (pad) b64 += '='.repeat(4 - pad);
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) u8[i]=bin.charCodeAt(i);
  return u8;
}
// simple CSV parser (handles quoted commas)
export function csvToObjects(csvText) {
  const lines = csvText.split('\n'); if(!lines.length) return [];
  const parseLine = (line) => {
    const res=[]; let cur='', inQ=false;
    for (let i=0;i<line.length;i++){
      const ch=line[i];
      if(ch==='"'){ if(inQ && line[i+1]==='"'){ cur+='"'; i++; } else inQ=!inQ; }
      else if(ch===',' && !inQ){ res.push(cur); cur=''; }
      else cur+=ch;
    }
    res.push(cur); return res;
  };
  const header = parseLine(lines[0]).map(h=>h.trim());
  const rows=[];
  for (let i=1;i<lines.length;i++){
    if(!lines[i].trim()) continue;
    const vals=parseLine(lines[i]); const obj={};
    for (let j=0;j<header.length;j++) obj[header[j]] = vals[j] || "";
    rows.push(obj);
  }
  return rows;
}
