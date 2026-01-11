import networkx as nx
import random
import heapq
from graph import visualize_graph


class Encryptor:
    def __init__(self, key="secret", degree=3):
        self.key = key
        self.degree = degree

    def xor_mix(self, value_list, weights):
        """Apply additive mixing using weights (for 0-25 range)"""
        mixed = []
        for i, val in enumerate(value_list):
            weight_val = weights[i % len(weights)]
            # Additive mixing with mod 26 (works in A-Z range)
            mixed_val = (val + weight_val) % 26
            mixed.append(mixed_val)
        return mixed

    def create_diffusion_graph(self, n):
        """Create graph from key and node count only.
        This allows decryption to rebuild the same graph without knowing plaintext.
        """
        G = nx.Graph()
        rng = random.Random(hash(self.key))

        # Create n nodes (no labels needed)
        for i in range(n):
            G.add_node(i)

        for i in range(n):
            neighbors = rng.sample(range(n), min(self.degree, n - 1))
            for j in neighbors:
                if i != j and not G.has_edge(i, j):
                    weight = rng.randint(1, 20)
                    G.add_edge(i, j, weight=weight)

        for i in range(n):
            current_degree = G.degree(i)
            if current_degree < self.degree:
                potential = [j for j in range(n) if j != i and not G.has_edge(i, j)]
                needed = self.degree - current_degree
                if len(potential) >= needed:
                    new_neighbors = rng.sample(potential, needed)
                    for j in new_neighbors:
                        weight = rng.randint(1, 20)
                        G.add_edge(i, j, weight=weight)
        # Ensure graph is connected by bridging components if necessary
        try:
            if not nx.is_connected(G) and G.number_of_nodes() > 0:
                components = list(nx.connected_components(G))
                for a, b in zip(components, components[1:]):
                    u = next(iter(a))
                    v = next(iter(b))
                    if not G.has_edge(u, v):
                        G.add_edge(u, v, weight=rng.randint(1, 20))
        except Exception:
            # If connectivity check fails (e.g., empty graph), just return as-is
            pass

        return G

    def shortest_path_distance(self, G, start, end):
        """Dijkstra shortest path"""
        distances = {node: float('inf') for node in G.nodes()}
        distances[start] = 0
        pq = [(0, start)]
        visited = set()

        while pq:
            dist, node = heapq.heappop(pq)
            if node in visited:
                continue
            visited.add(node)
            if node == end:
                return dist

            for neighbor in G.neighbors(node):
                w = G[node][neighbor]['weight']
                new_dist = dist + w
                if new_dist < distances[neighbor]:
                    distances[neighbor] = new_dist
                    heapq.heappush(pq, (new_dist, neighbor))

        return distances[end]

    def encrypt(self, plaintext):
        print(f"\n{'='*60}")
        print(f"ENCRYPTION")
        print(f"{'='*60}")
        print(f"Plaintext: {plaintext}")

        # Validate: only alphabetic characters supported
        if not plaintext.isalpha():
            print("WARNING: Non-alphabetic characters detected; use A-Z only.")

        # Step 1: Convert plaintext to values (0-25)
        plaintext_values = [ord(c.upper()) - ord('A') for c in plaintext if c.isalpha()]
        print(f"Plaintext values (0-25): {plaintext_values}")

        # Step 2: Create graph from key + length (not from plaintext values!)
        n = len(plaintext_values)
        G = self.create_diffusion_graph(n)
        print(f"\nGraph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
        
        # Print graph edges
        print("\n=== Graph Edges (u, v, weight) ===")
        edges = [(u, v, G[u][v]['weight']) for u, v in G.edges()]
        for u, v, w in sorted(edges):
            print(f"({u}, {v}, {w})")

        # Optional: visualize the graph
        visualize_graph(G, title=f"Encryption Graph for '{plaintext}'")

        # Step 3: Single-Source Shortest Path (SSSP) from node 0 to all nodes
        dijkstra_encrypted = []
        print("\n=== Single-Source Shortest Path from Node 0 ===")
        
        # Compute shortest paths from node 0 to all other nodes
        distances_from_0 = {}
        for target in range(n):
            distances_from_0[target] = self.shortest_path_distance(G, 0, target)
        
        # Encrypt each plaintext value using the distance from node 0
        for i in range(n):
            sp_distance = distances_from_0[i]
            plain_val = plaintext_values[i]
            encrypted_val = (plain_val + sp_distance) % 26
            dijkstra_encrypted.append(encrypted_val)
            print(f"  Node 0→{i}: distance={sp_distance}, ({plain_val} + {sp_distance}) % 26 = {encrypted_val}")

        # Step 4: Apply additive mixing using graph edge weights
        # Extract all edge weights to use as key
        edge_weights = [w for u, v, w in sorted(edges)]
        xor_mixed = self.xor_mix(dijkstra_encrypted, edge_weights)
        print(f"\n=== Additive Mixing (using edge weights) ===")
        print(f"Edge weights used: {edge_weights[:10]}{'...' if len(edge_weights) > 10 else ''}")
        print(f"After mixing: {xor_mixed}")
        
        # Convert to A-Z letters (already in 0-25 range)
        encrypted_text = "".join([chr(v + ord('A')) for v in xor_mixed])
        
        # Output format: encrypted_text | length | edges
        edges_str = ";".join([f"{u},{v},{w}" for u, v, w in sorted(edges)])
        full_output = f"{encrypted_text}|{len(plaintext)}|{edges_str}"
        
        print(f"\n{'='*60}")
        print(f"Encrypted Text: {encrypted_text}")
        print(f"Original Word: {plaintext}")
        return full_output


if __name__ == "__main__":
    plaintext = "broiambouttoblowthefuckup"
    key = "secret"
    
    encryptor = Encryptor(key=key, degree=3)
    encrypted_output = encryptor.encrypt(plaintext)
    
    print(f"\n{'='*60}")
    print("Send this to decryption:")
    print(encrypted_output)
    print(f"\nNote: No separate key needed - edge weights are the key!")
