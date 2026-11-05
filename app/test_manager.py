import csv,json,tempfile,unittest
from pathlib import Path
from managed_store import ManagedStore,UNASSIGNED

class ManagerTests(unittest.TestCase):
 def setUp(self):
  self.t=tempfile.TemporaryDirectory();self.r=Path(self.t.name)
  cats=[{'Artefacto':n,'Squad':s,'IT element':it,'Asignacion':a,'Observaciones':'nota','Secciones Word':refs,'Buscar como':n} for n,s,it,a,refs in [('api-a','A','IT1','Segun Word','A'),('api-b','A','IT2','Segun Word','A'),('api-ref','Por validar','IT1','Por validar','A | B')]]
  with (self.r/'Catalogo.csv').open('w',encoding='utf-8',newline='') as f:w=csv.DictWriter(f,fieldnames=list(cats[0]));w.writeheader();w.writerows(cats)
  images=[dict(Registry='reg',Repository=n,Tag='master-218-abcd',Id=n,Digest=n,Namespaces=['ns'],Clusters=['cl']) for n in ['api-a','api-b','api-ref']]
  (self.r/'inventario.json').write_text(json.dumps(dict(source='export.csv',source_modified=1,rows=3,images=images)))
  (self.r/'configuracion.json').write_text('{"version_objetivo":219}')
  self.s=ManagedStore(self.r)
 def tearDown(self):self.t.cleanup()
 def op(self,action,**kw):return self.s.mutate(dict(action=action,revision=self.s.state['revision'],**kw))
 def artifacts(self):return {a['name']:a for a in self.s.dataset()['artifacts']}
 def structure(self):return {g['name']:g['its'] for g in self.s.dataset()['structure']}
 def test_empty_squad_it_persistence_and_duplicate(self):
  self.op('manage.createSquad',name='New');self.op('manage.createIT',squad='New',name='IT-new')
  self.assertEqual(ManagedStore(self.r).dataset()['structure'],self.s.dataset()['structure'])
  with self.assertRaises(ValueError):self.op('manage.createSquad',name='new')
  self.op('manage.renameIT',squad='New',it='IT-new',name='IT-next');self.assertEqual(self.structure()['New'],['IT-next'])
  self.op('manage.deleteIT',squad='New',it='IT-next');self.assertEqual(self.structure()['New'],[])
  self.op('manage.deleteSquad',squad='New');self.assertNotIn('New',self.structure())
 def test_rename_preserves_images_and_multiple_membership(self):
  before=self.artifacts();self.op('manage.renameSquad',squad='A',name='Renamed');after=self.artifacts()
  self.assertNotIn('A',self.structure());self.assertEqual(after['api-a']['squads'],['Renamed'])
  self.assertIn('B',after['api-ref']['squads']);self.assertIn('Renamed',after['api-ref']['squads'])
  self.assertEqual(before['api-ref']['images'],after['api-ref']['images'])
  self.op('manage.renameIT',squad='Renamed',it='IT1',name='Updated');self.assertEqual(self.artifacts()['api-a']['it'],'Updated')
 def test_delete_moves_to_pending_without_losing_artifacts(self):
  self.op('manage.deleteSquad',squad='A');a=self.artifacts()
  self.assertEqual(len(a),3);self.assertNotIn('A',self.structure());self.assertEqual(a['api-a']['squads'],[UNASSIGNED]);self.assertEqual(a['api-a']['it'],'Por validar');self.assertIn('B',a['api-ref']['squads'])
  self.assertEqual(a['api-a']['versions'],[218])
  self.s=ManagedStore(self.r);self.assertNotIn('A',self.structure())
 def test_move_archive_restore_and_manual_edits_preserved(self):
  a=self.artifacts()['api-a'];self.op('save',id=a['id'],fields=dict(name=a['name'],squad='A',it='IT1',query=a['query'],notes='reunion',manualVersions='219',manualMode='replace',confirmAssignment=True))
  self.op('manage.createIT',squad='B',name='Destination');self.op('manage.move',ids=[a['id']],squad='B',it='Destination')
  current=self.artifacts()['api-a'];self.assertEqual(current['squads'],['B']);self.assertEqual(current['manualVersions'],'219');self.assertEqual(current['notes'],'reunion')
  self.op('manage.archive',ids=[a['id']]);self.assertTrue(self.artifacts()['api-a']['archived'])
  self.op('manage.restore',ids=[a['id']]);self.assertFalse(self.artifacts()['api-a']['archived'])
  current=self.artifacts()['api-a'];self.op('save',id=a['id'],fields=dict(name=a['name'],squad='A',it='IT2',query=a['query'],notes='reunion',manualVersions='219',manualMode='replace',confirmAssignment=True));self.assertEqual(self.artifacts()['api-a']['squads'],['A'])
 def test_delete_it_and_reimport_preserve_structure(self):
  self.op('manage.deleteIT',squad='A',it='IT1');self.assertNotIn('IT1',self.structure()['A']);self.assertEqual(self.artifacts()['api-a']['it'],'Por validar')
  self.op('manage.createSquad',name='Empty')
  inv=json.loads((self.r/'inventario.json').read_text());inv['source_modified']=2;(self.r/'inventario.json').write_text(json.dumps(inv))
  self.assertIn('Empty',self.structure());self.assertNotIn('IT1',self.structure()['A'])
 def test_stale_invalid_and_reserved_operations(self):
  with self.assertRaises(RuntimeError):self.s.mutate(dict(action='manage.deleteSquad',squad='A',revision=-1))
  with self.assertRaises(ValueError):self.op('manage.move',squad='A',it='absent',ids=[self.artifacts()['api-a']['id']])
  with self.assertRaises(ValueError):self.op('manage.deleteSquad',squad=UNASSIGNED)
  self.assertEqual(len(self.artifacts()),3)
 def test_project_assignment_updates_vulnerability_squads(self):
  finding={'id':'f1','cve':'CVE-2026-12345','severity':'HIGH','state':'ACTIVE','mute':'UNDEFINED','project':'demo-prod','squads':[UNASSIGNED]}
  (self.r/'gcp_vulnerabilities.json').write_text(json.dumps({'schema':'gcp-vulnerabilities-v1','available':True,'findings':[finding]}))
  self.assertEqual(self.s.dataset()['projects'][0]['squad'],UNASSIGNED)
  self.op('manage.createProject',project='demo-prod',squad='A')
  self.assertEqual(self.s.vulnerabilities()['findings'][0]['squads'],['A'])
  self.op('manage.moveProject',project='demo-prod',squad='B')
  self.assertEqual(self.s.vulnerabilities()['findings'][0]['squads'],['B'])
  self.op('manage.deleteProject',project='demo-prod')
  self.assertEqual(self.s.vulnerabilities()['findings'][0]['squads'],[UNASSIGNED])

if __name__=='__main__':unittest.main(verbosity=2)
