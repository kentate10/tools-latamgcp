export const priority={pending:0,review:1,missing:2,current:3};
export const escapeHTML=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const normalize=s=>String(s??'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
export function forSquad(artifacts,squad){return artifacts.filter(a=>!squad||a.squads.includes(squad));}
export function selectArtifacts(artifacts,{squad='',it='',status='all',search='',itSearch='',archived=false,target=null}={}){
 return forSquad(artifacts,squad).filter(a=>a.archived===archived&&(!itSearch||(a.itElements||[a.it]).some(v=>normalize(v).includes(normalize(itSearch.trim()))))&&(!it||(a.itElements||[a.it]).includes(it))&&(status==='all'||(status==='nocsv'?!a.csvFound:status==='imageCurrent'?a.effectiveImages.some(i=>i.version===target):a.status===status))&&(!search||normalize([a.name,(a.itElements||[a.it]).join(' '),a.notes,...a.effectiveImages.map(i=>i.tag)].join(' ')).includes(normalize(search)))).sort((a,b)=>priority[a.status]-priority[b.status]||a.name.localeCompare(b.name));
}
export function versionText(a,repeat=true){
 let vals=a.effectiveImages.map(i=>i.version===null?'Sin verificar':String(i.version));
 if(!repeat)vals=[...new Set(vals)];
 vals.sort((a,b)=>Number.isFinite(+a)&&Number.isFinite(+b)?+a-+b:a.localeCompare(b));
 let result=vals.join(', ')||'Sin revisión';
 if(!a.csvFound)result=vals.length?result+' (manual; no encontrado en GCP)':'No encontrado en GCP';
 else if(a.edited&&(a.manualVersions||a.images.some(i=>i.manual)))result+=' (revisión manual)';
 if(a.ambiguous&&a.manualMode!=='replace')result+=' (coincidencia por validar)';
 return result;
}
export function wordExport(artifacts,{squad='',headers=true,repeat=true}={}){
 const clean=s=>String(s??'').replace(/[\t\r\n]+/g,' ');
 const lines=[];let html='<html><body><div style="font-family:Calibri,Arial,sans-serif;font-size:11pt;color:#111">';
 if(headers){lines.push('Squad '+clean(squad||'Todos los squads'));html+='<p><b>Squad '+escapeHTML(squad||'Todos los squads')+'</b></p>';}
 const groups=new Map();
 for(const a of artifacts){const group=headers?(squad?'':a.squad+' / ')+'IT ELEMENT '+((a.itElements||[a.it]).join(' / ')||'Por validar'):'';if(!groups.has(group))groups.set(group,[]);groups.get(group).push(a);}
 for(const [group,rows] of groups){
  if(group){lines.push(group,'Artefacto\tVersión');html+='<p><b>'+escapeHTML(group)+'</b></p>';}
  html+='<table style="border-collapse:collapse;border:0;width:100%;table-layout:fixed"><colgroup><col style="width:80%"><col style="width:20%"></colgroup>';
  if(headers)html+='<tr><td style="border:0;width:80%"><b>Artefacto</b></td><td style="border:0;width:20%"><b>Versión</b></td></tr>';
  for(const a of [...rows].sort((a,b)=>priority[a.status]-priority[b.status]||a.name.localeCompare(b.name))){
   const v=versionText(a,repeat);lines.push(clean(a.name)+'\t'+clean(v));
   html+='<tr><td style="border:0;padding:2pt 12pt 2pt 0;vertical-align:top;overflow-wrap:anywhere">'+escapeHTML(a.name)+'</td><td style="border:0;padding:2pt 0;vertical-align:top">'+escapeHTML(v)+'</td></tr>';
  }
  html+='</table>';if(headers)lines.push('');
 }
 return {text:lines.join('\r\n').trimEnd(),html:html+'</div></body></html>'};
}
