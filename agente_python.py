from rdflib import Graph, Namespace
from rdflib.namespace import RDF, RDFS

# Cargar ontología
url = "https://raw.githubusercontent.com/AldoMonter19/ontologia-ciberseguridad/refs/heads/main/urn_webprotege_ontology_ae38c2d2-088a-469f-8390-3fa98e5d5a06.owl"
g = Graph()
g.parse(url, format="xml")

# Namespace correcto
ns = Namespace("http://www.miOntologia.org/ciberseguridad/")

class AgenteCiberseguridad:
    def __init__(self, grafo):
        self.grafo = grafo
    
    def recomendar(self, clase_amenaza):
        consulta = f"""
        SELECT ?label WHERE {{
            ?amenaza rdf:type <{clase_amenaza}> .
            ?control <{ns.RCLfujm9FxABZ3TA9keFTNX}> ?amenaza .
            ?control rdfs:label ?label .
        }}
        """
        resultados = self.grafo.query(consulta, initNs={"rdf": RDF, "rdfs": RDFS})
        return [str(r[0]) for r in resultados]

# Crear agente
agente = AgenteCiberseguridad(g)

# Consultar controles para amenazas tipo Phishing
controles = agente.recomendar(ns.RDpf999JXDe133XdpVACbwz)

print("Controles para Phishing:", controles)