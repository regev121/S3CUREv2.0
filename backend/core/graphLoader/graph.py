from enum import Enum


class NodeType(Enum):
    """
    Enumeration defining the semantic types of nodes within the analysis graph.
    Used for type-checking and visualization styling.
    """
    USER = "USER"
    POLICY = "POLICY"
    RESOURCE = "RESOURCE"


class SecurityGraph:
    def __init__(self):
        """
        Initializes the Security Graph Data Structure.
        Acts as the central registry for all entities (Nodes) and their relationships (Edges).

        Attributes:
            nodes (dict): A mapping of Unique Identifier -> NodeType.
            edges (list): A list of directional relationship dictionaries.
        """
        self.nodes = {}
        self.edges = []

    def add_node(self, name, node_type):
        """
        Registers a new entity in the graph if it is not already present.
        """
        if name not in self.nodes:
            self.nodes[name] = node_type

    def add_edge(self, source, target, relationship_type, metadata=None):
        """
        Establishes a directional relationship between two existing valid nodes.

        Args:
            source (str): origin node identifier.
            target (str): destination node identifier.
            relationship_type (str): semantic label for the connection (e.g., 'HAS_POLICY').
            metadata (dict, optional): additional context such as specific actions or conditions.

        Raises:
            ValueError: If either source or target nodes do not exist in the registry.
        """
        if source not in self.nodes:
            raise ValueError(f"Source node '{source}' does not exist.")
        if target not in self.nodes:
            raise ValueError(f"Target node '{target}' does not exist.")

        edge = {
            "source": source,
            "target": target,
            "type": relationship_type,
            "metadata": metadata or {},
        }
        self.edges.append(edge)

    def get_edges_from(self, source_name):
        """
        Retrieves all outbound relationships originating from the specified node.
        Effective for traversing the graph from User -> Policy -> Resource.
        """
        return [e for e in self.edges if e["source"] == source_name]

    def clear(self):
        """
        Resets the graph state, removing all nodes and edges.
        """
        self.nodes = {}
        self.edges = []
