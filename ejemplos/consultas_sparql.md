#Obtener amenazas y su nivel de riesgo (Probado y Funcional)
```
def obtener_amenazas_y_riesgo(self):

    consulta = f"""
    SELECT ?amenazaLabel ?riesgo WHERE {{

        ?tipoAmenaza rdfs:subClassOf <{ns.RBD9GzEY64WoWN7t9phfr6S}> .

        ?amenaza rdf:type ?tipoAmenaza .

        ?amenaza rdfs:label ?amenazaLabel .

        ?amenaza <{ns.RUfzM4EVMU3wpjIkKrxgu1}> ?riesgo .
    }}
    """

    resultados = self.grafo.query(
        consulta,
        initNs={"rdf": RDF, "rdfs": RDFS}
    )

    return [
        (str(r.amenazaLabel), int(r.riesgo))
        for r in resultados
    ]

# Consultar amenazas y riesgo
riesgos = agente.obtener_amenazas_y_riesgo()
print("\nAmenazas y niveles de riesgo:")
for amenaza, riesgo in riesgos:
    print(f"{amenaza}: Riesgo {riesgo}")
```
#Obtener controles y qué amenazas mitigan (Probado y Funcional)
```
def controles_y_amenazas(self):

        consulta = f"""
        SELECT ?controlLabel ?amenazaLabel WHERE {{

            ?control <{ns.RCLfujm9FxABZ3TA9keFTNX}> ?amenaza .

            ?control rdfs:label ?controlLabel .

            ?amenaza rdfs:label ?amenazaLabel .
        }}
        """

        resultados = self.grafo.query(
            consulta,
            initNs={"rdfs": RDFS}
        )

        return [
            (str(r.controlLabel), str(r.amenazaLabel))
            for r in resultados
        ]

# Mostrar relaciones
relaciones = agente.controles_y_amenazas()
print("\nRelaciones control → amenaza:")
for control, amenaza in relaciones:
    print(f"{control} mitiga {amenaza}")
```
#Obtener activos afectados por una amenaza (No Probado)
```
def activos_afectados(self, clase_amenaza):
    consulta = f"""
    SELECT ?activoLabel WHERE {{
        ?amenaza rdf:type <{clase_amenaza}> .
        ?amenaza <{ns.RB4Ysx7XORwu3Bv6QSm6g4P}> ?activo .
        ?activo rdfs:label ?activoLabel .
    }}
    """
    resultados = self.grafo.query(consulta, initNs={"rdf": RDF, "rdfs": RDFS})
    return [str(r.activoLabel) for r in resultados]
```
#Obtener políticas asociadas a un activo (No Probado)
```
def politicas_de_activo(self, activo_uri):
    consulta = f"""
    SELECT ?politicaLabel WHERE {{
        <{activo_uri}> <{ns.RIWL9vGdAExXblGJbyZuLh}> ?politica .
        ?politica rdfs:label ?politicaLabel .
    }}
    """
    resultados = self.grafo.query(consulta, initNs={"rdfs": RDFS})
    return [str(r.politicaLabel) for r in resultados]
```
#Obtener vulnerabilidades con fecha de detección (No Probado)
```
def vulnerabilidades_detectadas(self):
    consulta = f"""
    SELECT ?vulnLabel ?fecha WHERE {{
        ?vuln rdf:type <{ns.R7HjOSBzwL01OUs3szEKCF5}> .
        ?vuln rdfs:label ?vulnLabel .
        ?vuln <{ns.R9nDzARxpu32MYlLwjAc3jn}> ?fecha .
    }}
    """
    resultados = self.grafo.query(consulta, initNs={"rdf": RDF, "rdfs": RDFS})
    return [(str(r.vulnLabel), str(r.fecha)) for r in resultados]
```
#Obtener controles por tipo (Firewall, Antivirus, etc.) (No Probado)
```
def controles_por_tipo(self, tipo_control):
    consulta = f"""
    SELECT ?label WHERE {{
        ?control rdf:type <{tipo_control}> .
        ?control rdfs:label ?label .
    }}
    """
    resultados = self.grafo.query(consulta, initNs={"rdf": RDF, "rdfs": RDFS})
    return [str(r.label) for r in resultados]
```
#Consulta más completa (amenaza → activo → política → control) (No Probado)
```
def analisis_completo(self):
    consulta = f"""
    SELECT ?amenazaLabel ?activoLabel ?politicaLabel ?controlLabel WHERE {{
        ?amenaza rdf:type <{ns.RBD9GzEY64WoWN7t9phfr6S}> .
        ?amenaza rdfs:label ?amenazaLabel .
        
        ?amenaza <{ns.RB4Ysx7XORwu3Bv6QSm6g4P}> ?activo .
        ?activo rdfs:label ?activoLabel .
        
        ?activo <{ns.RIWL9vGdAExXblGJbyZuLh}> ?politica .
        ?politica rdfs:label ?politicaLabel .
        
        ?control <{ns.RCLfujm9FxABZ3TA9keFTNX}> ?amenaza .
        ?control rdfs:label ?controlLabel .
    }}
    """
    resultados = self.grafo.query(consulta, initNs={"rdf": RDF, "rdfs": RDFS})
    return [
        (str(r.amenazaLabel), str(r.activoLabel), str(r.politicaLabel), str(r.controlLabel))
        for r in resultados
    ]
