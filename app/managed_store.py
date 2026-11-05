"""Persistent squad/IT management layered over the existing image review."""
from interfaz.server import Store, now, text, read_json

UNASSIGNED = 'Por validar asignacion'
UNKNOWN_IT = 'Por validar'

def name(value):
    value = text(value, 160)
    if not value or any(ord(c) < 32 for c in value):
        raise ValueError('Escribe un nombre vÃ¡lido de hasta 160 caracteres')
    return value

class ManagedStore(Store):
    def dataset(self):
        with self.lock:
            data = super().dataset()
            for a in data['artifacts']:
                a['itElements'] = self.state['overrides'].get(a['id'], {}).get('itElements') or [a['it']]
                membership = self.state['overrides'].get(a['id'], {}).get('memberships')
                if membership is not None:
                    a['squads'] = membership or [UNASSIGNED]
            groups = {s: set(its) for s, its in self.state.get('squadDefs', {}).items()}
            for a in data['artifacts']:
                for s in a['squads']:
                    groups.setdefault(s, set()).update(a['itElements'])
            project_squads = self.state.setdefault('projectSquads', {})
            observed = set()
            vulnerability_path = self.root / 'gcp_vulnerabilities.json'
            if vulnerability_path.exists():
                observed.update(f.get('project') for f in read_json(vulnerability_path).get('findings', []) if f.get('project') and f.get('project') != 'No determinado')
            projects = sorted(observed | set(project_squads), key=str.casefold)
            data['projects'] = [{'name':project,'squad':project_squads.get(project,UNASSIGNED),'observed':project in observed} for project in projects]
            data['structure'] = [{'name':s, 'its':sorted(its, key=str.casefold)} for s,its in sorted(groups.items(), key=lambda pair:pair[0].casefold())]
            return data

    def vulnerabilities(self):
        with self.lock:
            path = self.root / 'gcp_vulnerabilities.json'
            if not path.exists(): return None
            result = read_json(path)
            mappings = self.state.get('projectSquads', {})
            for finding in result.get('findings', []):
                from scc_collect import classify_normalized_finding
                finding.setdefault('resourceCategory', classify_normalized_finding(finding))
                finding.setdefault('components', [])
                finding.setdefault('lastSeen', finding.get('eventTime') or finding.get('createTime'))
                assigned = mappings.get(finding.get('project'))
                if assigned and assigned != UNASSIGNED:
                    squads = [s for s in finding.get('squads', []) if s != UNASSIGNED]
                    finding['squads'] = sorted(set(squads + [assigned]))
            from scc_collect import summarize, summarize_categories
            result['counts'], result['bySquad'] = summarize(result.get('findings', []))
            result['byCategory'] = summarize_categories(result.get('findings', []))
            result['projectMappings'] = [{'project':project,'squad':squad} for project,squad in sorted(mappings.items())]
            return result

    def mutate(self, payload):
        with self.lock:
            if payload.get('revision') != self.state['revision']:
                raise RuntimeError('Otra ventana guardÃ³ cambios. Actualiza la vista antes de guardar.')
            action = payload.get('action', '')
            if not action.startswith('manage.'):
                if action == 'save':
                    ident = payload.get('id')
                    fields = payload.get('fields', {})
                    existing = next((a for a in self.dataset()['artifacts'] if a['id']==ident), None)
                    if existing and (fields.get('confirmAssignment') or fields.get('squad') != existing['squad']):
                        self.state['overrides'].get(ident, {}).pop('memberships', None)
                return super().mutate(payload)

            data = self.dataset()
            structure = {s['name']:s['its'] for s in data['structure']}
            defs = self.state.setdefault('squadDefs', {})
            squad = payload.get('squad', '')
            it = payload.get('it', '')
            artifacts = data['artifacts']

            def require_squad():
                if squad not in structure: raise ValueError('El squad ya no existe. Actualiza la vista.')
            def unique(new, values, old=None):
                if any(v.casefold()==new.casefold() and v!=old for v in values):
                    raise ValueError('Ya existe ese nombre; elige otro o mueve los artefactos al existente.')
            def patch(a, **fields):
                self.state['overrides'].setdefault(a['id'], {}).update(fields, structureEditedAt=now())

            if action == 'manage.setITs':
                values=payload.get('itElements')
                if not isinstance(values,list) or not 1<=len(values)<=50:raise ValueError('Indica entre 1 y 50 IT elements')
                values=list(dict.fromkeys(name(v) for v in values))
                a=next((a for a in artifacts if a['id']==payload.get('id')),None)
                if a is None:raise ValueError('Artefacto no encontrado')
                patch(a,it=values[0],itElements=values)
            elif action == 'manage.createSquad':
                new = name(payload.get('name'))
                if new.casefold() in (UNASSIGNED.casefold(), UNKNOWN_IT.casefold()): raise ValueError('Ese nombre estÃ¡ reservado')
                unique(new, structure); defs[new] = []
            elif action in ('manage.renameSquad', 'manage.deleteSquad'):
                require_squad()
                if squad == UNASSIGNED: raise ValueError('No se puede eliminar ni renombrar el grupo de asignaciones pendientes')
                new = name(payload.get('name')) if action=='manage.renameSquad' else None
                if new:
                    if new.casefold() in (UNASSIGNED.casefold(),UNKNOWN_IT.casefold()): raise ValueError('Ese nombre estÃ¡ reservado')
                    unique(new, structure, squad)
                    defs[new] = list(structure[squad])
                if new != squad: defs.pop(squad, None)
                for a in artifacts:
                    if squad not in a['squads']: continue
                    members = [new if s==squad else s for s in a['squads'] if s!=squad or new]
                    changes = {'memberships':members or [UNASSIGNED]}
                    if a['squad']==squad:
                        changes['squad'] = new or next((s for s in members if s!=UNASSIGNED), UNKNOWN_IT)
                    if not any(s!=UNASSIGNED for s in members):
                        changes.update(squad=UNKNOWN_IT,it=UNKNOWN_IT,assignmentConfirmed=False)
                    patch(a, **changes)
                project_squads=self.state.setdefault('projectSquads',{})
                for project,assigned in list(project_squads.items()):
                    if assigned==squad:project_squads[project]=new or UNASSIGNED
            elif action == 'manage.createIT':
                require_squad(); new=name(payload.get('name'))
                unique(new,structure[squad]);defs.setdefault(squad,[]).append(new)
            elif action in ('manage.renameIT','manage.deleteIT'):
                require_squad()
                if it not in structure[squad]: raise ValueError('El IT element ya no existe')
                if it==UNKNOWN_IT: raise ValueError('Asigna los artefactos pendientes a un IT element concreto')
                new=name(payload.get('name')) if action=='manage.renameIT' else UNKNOWN_IT
                if new!=UNKNOWN_IT: unique(new,structure[squad],it)
                defs[squad]=[v for v in defs.get(squad,[]) if v!=it]
                if action=='manage.renameIT' and new not in defs[squad]:defs[squad].append(new)
                for a in artifacts:
                    if squad in a['squads'] and it in a['itElements']:
                        elements=[new if v==it else v for v in a['itElements'] if v!=it or action=='manage.renameIT'] or [UNKNOWN_IT]
                        patch(a,it=elements[0],itElements=list(dict.fromkeys(elements)))
            elif action in ('manage.move','manage.archive','manage.restore'):
                ids=payload.get('ids')
                if not isinstance(ids,list) or not ids or len(ids)>2000 or any(not isinstance(i,str) for i in ids):raise ValueError('Selecciona al menos un artefacto')
                by_id={a['id']:a for a in artifacts}
                if len(set(ids))!=len(ids) or any(i not in by_id for i in ids):raise ValueError('La selecciÃ³n ya no es vÃ¡lida. Actualiza la vista.')
                if action=='manage.move':
                    require_squad()
                    if squad==UNASSIGNED:raise ValueError('Elige un squad concreto para confirmar la asignaciÃ³n')
                    if it!=UNKNOWN_IT and it not in structure[squad]:raise ValueError('Selecciona un IT element del squad de destino')
                    for ident in ids:patch(by_id[ident],squad=squad,it=it,itElements=[it],memberships=[squad],assignmentConfirmed=True)
                else:
                    for ident in ids:patch(by_id[ident],archived=action=='manage.archive')
            elif action in ('manage.createProject','manage.moveProject','manage.deleteProject'):
                project=text(payload.get('project',''),128)
                if not project or any(ord(c)<32 for c in project):raise ValueError('Escribe un project ID válido')
                project_squads=self.state.setdefault('projectSquads',{})
                if action=='manage.createProject' and project in project_squads:raise ValueError('Ese proyecto ya tiene una asignación manual')
                if action=='manage.deleteProject':
                    if project not in project_squads:raise ValueError('El proyecto no tiene una asignación manual')
                    project_squads.pop(project)
                else:
                    require_squad()
                    if squad==UNASSIGNED:raise ValueError('Elige un squad concreto para asignar el proyecto')
                    project_squads[project]=squad
            else: raise ValueError('AcciÃ³n de gestiÃ³n desconocida')
            self.commit()
            return self.dataset()
