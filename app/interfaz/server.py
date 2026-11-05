"""Tools LatamGCP local. Solo biblioteca estándar; escucha en loopback."""
import argparse,copy,csv,hashlib,json,os,re,secrets,shutil,sys,threading,time,uuid,webbrowser
from datetime import datetime,timezone
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs,urlparse

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
sys.path.insert(0,str(ROOT))
from gcp_collect import active_gcloud_account, collect_inventory
from scc_collect import SAFE_CVE, collect_vulnerabilities, query_exact_cve
from bigquery_live import query_artifacts,query_cmdb,query_dashboard,query_project_squads
import scc_browse,squad_beta
import artifact_lookup
from image_rules import base_versions, interpreted_version
APP_ID='tools-latam-gcp-local-v1'

def now():return datetime.now(timezone.utc).isoformat()
def key(s):return hashlib.sha256(s.encode()).hexdigest()[:24]
def values(items):return ', '.join(sorted({x.strip() for v in items for x in v.split(',') if x.strip()}))
def read_json(p):return json.loads(p.read_text(encoding='utf-8-sig'))
def atomic(p,obj):
    tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(obj,ensure_ascii=False,indent=2),encoding='utf-8');os.replace(tmp,p)
def text(value,limit=1000):
    if not isinstance(value,str) or len(value)>limit:raise ValueError('Texto no valido o demasiado largo')
    return value.strip()
def interpreted(tag):
    return interpreted_version(tag)

class Store:
    def __init__(self,root=ROOT):
        self.root=Path(root);self.dir=self.root/'interfaz'/'datos';self.dir.mkdir(parents=True,exist_ok=True)
        self.path=self.dir/'ediciones.json';self.lock=threading.RLock()
        self.state=read_json(self.path) if self.path.exists() else {'revision':0,'overrides':{},'custom':{},'target':None}
        self.signature=None;self.inventory=None;self.catalog=None
        self.job={'status':'idle','message':''}
        self.cve_jobs={}
        self.gcloud_check={'checkedAt':0,'status':'unknown'}
        self.latest_live_vulnerabilities=None
        self.live_vulnerability_projects=set()
        self.live_jobs={}
    def load(self):
        def mtime(name):
            path=self.root/name
            return path.stat().st_mtime_ns if path.exists() else 0
        sig=tuple(mtime(n) for n in ['inventario.json','Catalogo.csv','configuracion.json'])
        if sig!=self.signature:
            inventory_path=self.root/'inventario.json';catalog_path=self.root/'Catalogo.csv'
            self.inventory=read_json(inventory_path) if inventory_path.exists() else {'schema':'vacio','source':'Sin inventario local (solo consultas en vivo)','source_modified':0,'collected_at':'','rows':0,'images':[],'repositories':[]}
            if catalog_path.exists():
                with catalog_path.open(encoding='utf-8-sig',newline='') as f:self.catalog=list(csv.DictReader(f))
            else:self.catalog=[]
            self.config=read_json(self.root/'configuracion.json');self.signature=sig
    def commit(self):
        if self.path.exists():shutil.copy2(self.path,self.path.with_suffix('.bak.json'))
        self.state['revision']+=1;self.state['updatedAt']=now();atomic(self.path,self.state)
    def dataset(self):
        with self.lock:
            self.load();target=self.state['target'] or self.config['version_objetivo'];by={}
            for im in self.inventory['images']:
                by.setdefault(im['Repository'].rsplit('/',1)[-1].lower(),[]).append(im)
            cats=[(key(c['Artefacto'].lower()),c,False) for c in self.catalog]
            cats += [(ident,c,True) for ident,c in self.state['custom'].items()]
            artifacts=[]
            for ident,c,custom in cats:
                o=self.state['overrides'].get(ident,{})
                name=o.get('name',c['Artefacto']);squad=o.get('squad',c['Squad']);it=o.get('it',c['IT element'])
                query=o.get('query',c['Buscar como']).lower()
                if '/' in query:
                    ims=[im for im in self.inventory['images'] if query in (im['Repository'].lower(),(im['Registry']+'/'+im['Repository']).lower())]
                else:ims=by.get(query,[])
                current_ims=[im for im in ims if not im.get('missing',False)]
                families={im['Registry']+'/'+re.sub(r'/application-(?:master|develop|stg|dev|prod|intg)/','/application/',im['Repository']) for im in current_ims}
                ambiguous=len(families)>1 or query in {'api','web'} or query.endswith('-')
                images=[]
                for im in ims:
                    iid=key('\0'.join(im.get(k,'') for k in ['Registry','Repository','Tag','Id','Digest']))
                    original={'tag':im['Tag'],'namespace':values(im['Namespaces']),'cluster':values(im['Clusters'])}
                    patch=o.get('imageEdits',{}).get(iid,{})
                    image={**original,**patch,'id':iid,'source':im.get('source','Inventario inicial'),'original':original,'registry':im['Registry'],'repository':im['Repository'],'digest':im['Digest'],'imageId':im['Id'],'missing':bool(im.get('missing',False)),'lastSeenSource':im.get('lastSeenSource','')}
                    image['manual']=bool(patch)
                    bases=base_versions(im);tag_version=interpreted(image['tag'])
                    manual_base=patch.get('baseVersion','')
                    if manual_base:
                        image['version']=int(manual_base);image['versionSource']='base_version verificado manualmente'
                    elif bases:
                        image['version']=bases[0] if len(bases)==1 else None;image['versionSource']='label base_version'
                    else:
                        image['version']=tag_version;image['versionSource']='tag' if tag_version is not None else 'Sin base_version en el resumen'
                    image['versionConflict']=len(bases)>1 or (bool(bases) and tag_version is not None and tag_version not in bases)
                    image['labelBaseVersions']=bases
                    images.append(image)
                manual_tags=[s.strip() for s in re.split(r'[,;\n]+',o.get('manualVersions','')) if s.strip()]
                manual=[{'id':f'manual-{i}','tag':t,'version':interpreted(t),'source':'Manual','manual':True,'namespace':'','cluster':'','note':o.get('notes',''),'missing':not any(not im['missing'] and (im['tag']==t or (interpreted(t) is not None and im['version']==interpreted(t))) for im in images)} for i,t in enumerate(manual_tags)]
                active=[im for im in images if not im.get('excluded',False) and not im['missing']]
                effective=manual if o.get('manualMode')=='replace' else active+manual
                nums=[im['version'] for im in effective if im['version'] is not None]
                unknown=len(effective)-len(nums)
                if any(v!=target for v in nums):status='pending'
                elif not effective:status='missing' if not current_ims else 'review'
                elif any(im.get('versionConflict') for im in effective) or unknown or (ambiguous and o.get('manualMode')!='replace'):status='review'
                else:status='current'
                assignment='Confirmada manualmente' if o.get('assignmentConfirmed') or custom else c['Asignacion']
                refs=c.get('Secciones Word','').split(' | ')
                squads=[squad] if squad and squad!='Por validar' else []
                if assignment=='Por validar':squads=list(set(squads+[s for s in refs if s]+['Por validar asignacion']))
                if not squads:squads=['Por validar asignacion']
                artifacts.append({'id':ident,'name':name,'squad':squad,'squads':sorted(squads),'it':it or 'Por validar','assignment':assignment,'notes':o.get('notes',c['Observaciones']),'query':query,'originalName':c['Artefacto'],'referenceSquads':refs,'images':images,'manualImages':manual,'effectiveImages':effective,'versions':sorted(nums),'unknown':unknown,'status':status,'csvFound':bool(current_ims),'ambiguous':ambiguous,'custom':custom,'edited':bool(o),'archived':o.get('archived',False),'manualVersions':o.get('manualVersions',''),'manualMode':o.get('manualMode','supplement'),'editedAt':o.get('editedAt'),'hasOldManual':bool(o.get('editedAt') and self.inventory['source_modified']>datetime.fromisoformat(o['editedAt']).timestamp())})
            return {'revision':self.state['revision'],'target':target,'artifacts':artifacts,'meta':{'filename':self.inventory.get('source','Inventario local'),'schema':self.inventory.get('schema','latam-panel-images-seed'),'collectedAt':self.inventory.get('collected_at'),'modified':self.inventory['source_modified'],'rows':self.inventory['rows'],'images':self.inventory.get('source_images',sum(not im.get('missing',False) for im in self.inventory['images'])),'missingImages':self.inventory.get('missing_images',sum(bool(im.get('missing',False)) for im in self.inventory['images'])),'staleImages':self.inventory.get('stale_images',sum(bool(im.get('stale',False)) for im in self.inventory['images'])),'repositories':self.inventory.get('repositories',[]),'updatedAt':self.state.get('updatedAt')},'job':self.job}
    def client_dataset(self,include_inventory=False):
        """El catálogo se carga sin presentar el snapshot GCP como una consulta actual."""
        data=copy.deepcopy(self.dataset())
        data['inventoryRequested']=bool(include_inventory)
        data['meta']['mode']='requested-live' if include_inventory else 'catalog-only'
        data['meta']['cachedInventoryAvailable']=bool(self.inventory.get('images'))
        if include_inventory:return data
        for artifact in data['artifacts']:
            artifact['images']=[];artifact['manualImages']=[];artifact['effectiveImages']=[]
            artifact['versions']=[];artifact['unknown']=0;artifact['csvFound']=None
            artifact['status']='idle';artifact['queryStatus']='not_requested'
        return data
    def mutate(self,payload):
        with self.lock:
            if payload.get('revision')!=self.state['revision']:raise RuntimeError('Otra ventana guardo cambios. Actualiza el panel antes de guardar de nuevo.')
            action=payload.get('action')
            if action=='target':
                v=payload.get('target')
                if type(v)!=int or not 1<=v<=999:raise ValueError('La version objetivo debe ser un entero entre 1 y 999')
                self.state['target']=v
            elif action in ('save','add','archive','restore','image','resetImages','resetManual'):
                existing={a['id']:a for a in self.dataset()['artifacts']}
                ident=payload.get('id')
                if action=='add':ident='manual_'+uuid.uuid4().hex
                elif ident not in existing:raise ValueError('Artefacto no encontrado')
                patch={**self.state['overrides'].get(ident,{})}
                if action in ('save','add'):
                    fields=payload.get('fields',{});clean={k:text(fields.get(k,''),lim) for k,lim in [('name',200),('squad',160),('it',160),('query',500),('notes',5000),('manualVersions',5000)]}
                    if not clean['name'] or not clean['squad']:raise ValueError('Nombre y squad son obligatorios')
                    if any(a['name'].casefold()==clean['name'].casefold() and a['id']!=ident for a in existing.values()):raise ValueError('Ya existe ese artefacto. Edita el registro existente.')
                    if 'itElements' in fields:
                        parts=list(dict.fromkeys(v.strip() for v in text(fields['itElements'],5000).split(',') if v.strip()))
                        if len(parts)>50 or any(len(v)>160 for v in parts):raise ValueError('IT elements no validos')
                        clean['itElements']=list(dict.fromkeys([clean['it']]+parts))
                    elif clean['it']!=existing.get(ident,{}).get('it'):clean['itElements']=[clean['it']]
                    clean['query']=clean['query'] or clean['name'];mode=fields.get('manualMode','supplement')
                    if mode not in ('supplement','replace'):raise ValueError('Modo de revision no valido')
                    if mode=='replace' and not any(s.strip() for s in re.split(r'[,;\n]+',clean['manualVersions'])):raise ValueError('Ingresa al menos una version para usar tu revision manual')
                    clean['manualMode']=mode;clean['assignmentConfirmed']=bool(fields.get('confirmAssignment',False)) or action=='add';patch.update(clean)
                    if action=='add':self.state['custom'][ident]={'Artefacto':clean['name'],'Squad':clean['squad'],'IT element':clean['it'],'Asignacion':'Manual','Observaciones':'','Secciones Word':'','Buscar como':clean['query']}
                elif action in ('archive','restore'):patch['archived']=action=='archive'
                elif action=='resetManual':patch['manualVersions']='';patch['manualMode']='supplement'
                elif action=='resetImages':patch['imageEdits']={}
                elif action=='image':
                    iid=payload.get('imageId');images={im['id']:im for im in existing[ident]['images']}
                    if iid not in images:raise ValueError('Imagen no encontrada en la exportacion actual')
                    fields=payload.get('fields',{})
                    edits={**patch.get('imageEdits',{})}
                    if payload.get('reset'):edits.pop(iid,None)
                    else:
                        base=text(fields.get('baseVersion',''),4)
                        if base and not re.fullmatch(r'\d{1,4}',base):raise ValueError('Imagen base debe ser un numero de hasta 4 digitos')
                        edits[iid]={k:text(fields.get(k,''),lim) for k,lim in [('tag',300),('namespace',2000),('cluster',2000),('note',3000)]}
                        edits[iid]['baseVersion']=base;edits[iid]['excluded']=bool(fields.get('excluded',False))
                    patch['imageEdits']=edits
                patch['editedAt']=now();self.state['overrides'][ident]=patch
            else:raise ValueError('Accion desconocida')
            self.commit();return self.dataset()
    def refresh(self,source='artifacts'):
        if source!='artifacts':raise ValueError('Consulta no soportada. Usa una búsqueda CVE exacta para SCC.')
        with self.lock:
            if self.job['status']=='running':raise ValueError('Ya hay una actualización de GCP en curso')
            self.job={'status':'running','source':'artifacts','startedAt':now(),'message':'Consultando Artifact Registry en modo read-only…'}
        def task():
            completed=[];errors=[]
            self.load()
            try:
                collect_inventory(self.root)
                completed.append('Artifact Registry')
            except Exception as e:errors.append('Artifact Registry: '+str(e))
            with self.lock:
                self.signature=None
                if completed:
                    message='Consulta terminada: '+', '.join(completed)+'. Se conservaron squads, artefactos y ediciones manuales.'
                    if errors:message+=' Limitaciones: '+' | '.join(errors)
                    self.job={'status':'done','source':'artifacts','completedAt':now(),'message':message}
                else:self.job={'status':'error','source':'artifacts','completedAt':now(),'message':' | '.join(errors)}
        threading.Thread(target=task,daemon=True).start()
    def gcloud_status(self):
        with self.lock:
            if time.time()-self.gcloud_check.get('checkedAt',0)<30:return self.gcloud_check
        try:
            self.load();account=active_gcloud_account(self.config)
            result={'checkedAt':time.time(),'status':'ready','account':account,'organization':str(self.config.get('organization_id','')),'message':'gcloud tiene una cuenta activa y está listo para consultas read-only.'}
        except Exception as error:
            result={'checkedAt':time.time(),'status':'error','account':'','message':str(error)[-1000:]}
        with self.lock:self.gcloud_check=result
        return result
    def start_cve_search(self,cve):
        normalized=str(cve or '').strip().upper()
        if not SAFE_CVE.fullmatch(normalized):raise ValueError('Usa un CVE válido, por ejemplo CVE-2026-12345')
        with self.lock:
            for job_id,job in self.cve_jobs.items():
                if job.get('status')=='running':
                    if job.get('cve')==normalized:return {'jobId':job_id,'status':'running','cve':normalized}
                    raise ValueError('Ya hay otra consulta CVE en curso. Espera a que termine.')
            job_id=uuid.uuid4().hex
            self.cve_jobs[job_id]={'jobId':job_id,'status':'running','cve':normalized,'startedAt':now(),'message':'Consultando SCC sin límite configurado…'}
            while len(self.cve_jobs)>20:self.cve_jobs.pop(next(iter(self.cve_jobs)))
        def task():
            try:
                result=self.limit_for_ui(self.prepare_vulnerability_result(query_exact_cve(normalized,self.root)))
                self.latest_live_vulnerabilities=result
                self.live_vulnerability_projects={item.get('project') for item in result.get('findings',[]) if item.get('project') and item.get('project')!='No determinado'}
                completed={'jobId':job_id,'status':'done','cve':normalized,'startedAt':self.cve_jobs[job_id]['startedAt'],'completedAt':now(),'message':f"Consulta completada: {result['rows']} hallazgos.",'result':result}
            except Exception as error:
                completed={'jobId':job_id,'status':'error','cve':normalized,'startedAt':self.cve_jobs[job_id]['startedAt'],'completedAt':now(),'message':str(error)[-4000:]}
            with self.lock:self.cve_jobs[job_id]=completed
        threading.Thread(target=task,daemon=True).start()
        return {'jobId':job_id,'status':'running','cve':normalized}
    UI_DETAIL_LIMIT=5000
    def limit_for_ui(self,result):
        """El navegador recibe totales exactos y a lo sumo UI_DETAIL_LIMIT filas; la evidencia completa queda en disco."""
        rows=result.get('findings',[])
        result['stats']={'total':len(rows),'active':sum(f.get('state')=='ACTIVE' for f in rows),'inactive':sum(f.get('state')=='INACTIVE' for f in rows),'muted':sum(f.get('mute')=='MUTED' for f in rows),'projects':len({f.get('project') for f in rows if f.get('project')})}
        result['detailTruncated']=len(rows)>self.UI_DETAIL_LIMIT
        if result['detailTruncated']:
            order={'ACTIVE':0,'INACTIVE':1}
            result['findings']=sorted(rows,key=lambda f:(order.get(f.get('state'),2),f.get('lastSeen') or ''),reverse=False)[:self.UI_DETAIL_LIMIT]
        return result
    def prepare_vulnerability_result(self,result):
        """Enriquece en vivo con la CMDB. Si falla, el resultado SCC se conserva y el motivo queda explícito."""
        projects={f.get('project') for f in result.get('findings',[])}
        try:
            mapping=query_project_squads(projects,self.root)
            result['cmdbEnrichment']={'status':'ok','source':'techgov-data-prod.cmdb_data_metrics','projectsMatched':len(mapping),'projectsQueried':len({p for p in projects if p and p!='No determinado'})}
            for f in result.get('findings',[]):
                items=mapping.get(f.get('project'),[])
                f['cmdb']=items
                if items:f['squads']=sorted({i['squad'] for i in items if i.get('squad')}) or f['squads']
        except Exception as error:
            result['cmdbEnrichment']={'status':'error','message':str(error)[-500:]}
        return result
    def image_cves(self,payload):
        return scc_browse.image_cves(payload.get('digest'),payload.get('filters') or {},payload.get('pageToken') or '',payload.get('pageSize') or 100,payload.get('withFacets') is True,self.root)
    def image_lookup(self,payload):
        return artifact_lookup.lookup(payload.get('query'),self.root)
    def cve_facets(self,payload):
        return scc_browse.facets(payload.get('cve'),payload.get('filters') or {},self.root)
    def cve_page(self,payload):
        out=scc_browse.page(payload.get('cve'),payload.get('filters') or {},payload.get('pageToken') or '',payload.get('pageSize') or 100,self.root)
        self.prepare_vulnerability_result(out)
        return out
    def cve_job(self,job_id):
        if not re.fullmatch(r'[0-9a-f]{32}',job_id or ''):raise ValueError('Job CVE no válido')
        with self.lock:
            if job_id not in self.cve_jobs:raise KeyError('Consulta CVE no encontrada')
            return self.cve_jobs[job_id]
    def start_live_query(self,kind,payload):
        if kind not in ('dashboard','artifacts','cmdb','squadbeta'):raise ValueError('Tipo de consulta no soportado')
        with self.lock:
            if any(job.get('status')=='running' and job.get('kind')==kind for job in self.live_jobs.values()):
                raise ValueError(f'Ya hay una consulta {kind} en curso')
            job_id=uuid.uuid4().hex
            self.live_jobs[job_id]={'jobId':job_id,'kind':kind,'status':'running','startedAt':now(),'message':'Consultando GCP en vivo…'}
            while len(self.live_jobs)>20:self.live_jobs.pop(next(iter(self.live_jobs)))
        def task():
            try:
                if kind=='dashboard':
                    result=query_dashboard(payload.get('startDate'),payload.get('endDate'),payload.get('filters') or {},self.root)
                elif kind=='artifacts':
                    result=query_artifacts(payload.get('search',''),payload.get('squad',''),self.root)
                elif kind=='squadbeta':result=squad_beta.collect(payload.get('squad',''),self.root)
                else:result=query_cmdb(self.root)
                completed={'jobId':job_id,'kind':kind,'status':'done','startedAt':self.live_jobs[job_id]['startedAt'],'completedAt':now(),'message':f'Consulta {kind} completada.','result':result}
            except Exception as error:
                completed={'jobId':job_id,'kind':kind,'status':'error','startedAt':self.live_jobs[job_id]['startedAt'],'completedAt':now(),'message':str(error)[-4000:]}
            with self.lock:self.live_jobs[job_id]=completed
        threading.Thread(target=task,daemon=True).start()
        return {'jobId':job_id,'kind':kind,'status':'running'}
    def live_job(self,job_id):
        if not re.fullmatch(r'[0-9a-f]{32}',job_id or ''):raise ValueError('Job no válido')
        with self.lock:
            if job_id not in self.live_jobs:raise KeyError('Consulta no encontrada; el servidor pudo haberse reiniciado')
            return self.live_jobs[job_id]

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def allowed(self):return self.headers.get('Host') in self.server.hosts
    def send(self,status,data,ctype='application/json; charset=utf-8'):
        raw=json.dumps(data,ensure_ascii=False).encode() if 'json' in ctype else data
        self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(raw)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer');self.send_header('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        if not self.allowed():return self.send(403,{'error':'Host no permitido'})
        parsed=urlparse(self.path);route=parsed.path;query=parse_qs(parsed.query)
        try:
            if route=='/api/health':return self.send(200,{'app':APP_ID})
            if route=='/api/session':return self.send(200,{'app':APP_ID,'token':self.server.token,'mode':'live-gcp-only'})
            if route=='/api/data':
                include_inventory=query.get('inventory',['0'])==['1']
                return self.send(200,{**self.server.store.client_dataset(include_inventory),'token':self.server.token})
            if route=='/api/job':return self.send(200,self.server.store.job)
            if route=='/api/backup':return self.send(200,self.server.store.state)
            if route=='/api/gcp/status':
                path=self.server.store.root/'gcp_status.json'
                return self.send(200,read_json(path) if path.exists() else {'schema':'latam-gcp-status-v1','status':'unknown'})
            if route=='/api/gcloud/status':return self.send(200,self.server.store.gcloud_status())
            if route.startswith('/api/cve/jobs/'):
                return self.send(200,self.server.store.cve_job(route.rsplit('/',1)[-1]))
            if route.startswith('/api/live/jobs/'):
                return self.send(200,self.server.store.live_job(route.rsplit('/',1)[-1]))
            if route=='/api/vulnerabilities':
                if hasattr(self.server.store,'vulnerabilities'):
                    value=self.server.store.vulnerabilities()
                    if value is not None:return self.send(200,value)
                return self.send(200,{'schema':'gcp-vulnerabilities-v1','available':False,'status':'idle','source':'GCP Security Command Center','message':'No se ha ejecutado una consulta CVE en esta sesión.'})
            files={'/theme.js':('theme.js','text/javascript; charset=utf-8'),'/bootstrap.js':('bootstrap.js','text/javascript; charset=utf-8'),'/':('index.html','text/html; charset=utf-8'),'/app.js':('app.js','text/javascript; charset=utf-8'),'/core.js':('core.js','text/javascript; charset=utf-8'),'/manager.js':('manager.js','text/javascript; charset=utf-8'),'/style.css':('style.css','text/css; charset=utf-8')}
            if route in files:
                name,ctype=files[route];return self.send(200,(HERE/name).read_bytes(),ctype)
            self.send(404,{'error':'No encontrado'})
        except KeyError as e:self.send(404,{'error':str(e).strip("'")})
        except (ValueError,TypeError) as e:self.send(400,{'error':str(e)})
        except Exception as e:self.send(500,{'error':str(e)})
    def do_POST(self):
        if not self.allowed() or self.headers.get('X-Tools-Token')!=self.server.token:return self.send(403,{'error':'Solicitud no autorizada'})
        origin=self.headers.get('Origin')
        if origin and origin not in ['http://'+h for h in self.server.hosts]:return self.send(403,{'error':'Origen no permitido'})
        try:
            route=urlparse(self.path).path
            try:size=int(self.headers.get('Content-Length','0'))
            except ValueError:raise ValueError('Content-Length no válido')
            if size<0:raise ValueError('Content-Length no válido')
            if route=='/api/upload':raise ValueError('La carga manual fue deshabilitada. Usa Actualizar desde GCP.')
            if size>100000:raise ValueError('Solicitud demasiado grande')
            try:payload=json.loads(self.rfile.read(size) or '{}')
            except json.JSONDecodeError:raise ValueError('JSON de solicitud no válido')
            if not isinstance(payload,dict):raise ValueError('La solicitud debe ser un objeto JSON')
            if route=='/api/mutate':
                self.server.store.mutate(payload)
                include_inventory=payload.get('includeInventory') is True
                return self.send(200,self.server.store.client_dataset(include_inventory))
            if route=='/api/refresh':self.server.store.refresh(payload.get('source','artifacts'));return self.send(202,{'ok':True,'source':'artifacts'})
            if route=='/api/image/cves':return self.send(200,self.server.store.image_cves(payload))
            if route=='/api/image/lookup':return self.send(200,self.server.store.image_lookup(payload))
            if route=='/api/cve/facets':return self.send(200,self.server.store.cve_facets(payload))
            if route=='/api/cve/page':return self.send(200,self.server.store.cve_page(payload))
            if route=='/api/cve/search':return self.send(202,self.server.store.start_cve_search(payload.get('cve')))
            if route=='/api/live/dashboard':return self.send(202,self.server.store.start_live_query('dashboard',payload))
            if route=='/api/live/artifacts':return self.send(202,self.server.store.start_live_query('artifacts',payload))
            if route=='/api/live/squadbeta':return self.send(202,self.server.store.start_live_query('squadbeta',payload))
            if route=='/api/squadbeta/versions':return self.send(200,squad_beta.versions(payload.get('query'),self.server.store.root))
            if route=='/api/squadbeta/squads':return self.send(200,squad_beta.squads(self.server.store.root))
            if route=='/api/live/cmdb':return self.send(202,self.server.store.start_live_query('cmdb',payload))
            self.send(404,{'error':'No encontrado'})
        except RuntimeError as e:self.send(409,{'error':str(e)})
        except (ValueError,KeyError,TypeError) as e:self.send(400,{'error':str(e)})
        except Exception as e:self.send(500,{'error':str(e)})

def make_server(port=8765,store=None):
    server=ThreadingHTTPServer(('127.0.0.1',port),Handler);server.daemon_threads=True
    server.store=store or Store();server.token=secrets.token_urlsafe(32)
    actual=server.server_address[1];server.hosts={f'127.0.0.1:{actual}',f'localhost:{actual}'}
    return server

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--open',action='store_true');parser.add_argument('--port',type=int,default=8765);args=parser.parse_args()
    url=f'http://127.0.0.1:{args.port}'
    try:server=make_server(args.port)
    except OSError:
        from urllib.request import urlopen
        try:
            with urlopen(url+'/api/health',timeout=2) as r:healthy=json.load(r).get('app')==APP_ID
        except Exception:healthy=False
        if not healthy:raise SystemExit('El puerto esta ocupado por otra aplicacion')
        if args.open:webbrowser.open(url)
        raise SystemExit(0)
    print('Panel local: '+url,flush=True)
    if args.open:threading.Timer(.6,lambda:webbrowser.open(url)).start()
    try:server.serve_forever()
    except KeyboardInterrupt:pass
    finally:server.server_close()

