from rdflib import Graph, Namespace
from rdflib.namespace import RDF, RDFS

# Cargar ontología
url = "https://raw.githubusercontent.com/AldoMonter19/ontologia-ciberseguridad/refs/heads/main/urn_webprotege_ontology_ae38c2d2-088a-469f-8390-3fa98e5d5a06.owl"

g = Graph()
g.parse(url, format="xml")

# Namespace
ns = Namespace("http://www.miOntologia.org/ciberseguridad/")

class AgenteCiberseguridad:

    def __init__(self, grafo):
        self.grafo = grafo

    # Método original
    def recomendar(self, clase_amenaza):

        consulta = f"""
        SELECT ?label WHERE {{
            ?amenaza rdf:type <{clase_amenaza}> .
            ?control <{ns.RCLfujm9FxABZ3TA9keFTNX}> ?amenaza .
            ?control rdfs:label ?label .
        }}
        """

        resultados = self.grafo.query(
            consulta,
            initNs={"rdf": RDF, "rdfs": RDFS}
        )

        return [str(r[0]) for r in resultados]

    # Nuevo método
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

    # Controles y amenazas
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

# Crear agente
agente = AgenteCiberseguridad(g)

# Consultar controles
controles = agente.recomendar(ns.RDpf999JXDe133XdpVACbwz)
print("Controles para Phishing:", controles)

# Consultar amenazas y riesgo
riesgos = agente.obtener_amenazas_y_riesgo()
print("\nAmenazas y niveles de riesgo:")
for amenaza, riesgo in riesgos:
    print(f"{amenaza}: Riesgo {riesgo}")

# Mostrar relaciones
relaciones = agente.controles_y_amenazas()
print("\nRelaciones control → amenaza:")
for control, amenaza in relaciones:
    print(f"{control} mitiga {amenaza}")
