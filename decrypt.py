"""
Decryption module - works independently with encrypted output + key
"""
import networkx as nx
import random
import heapq


class Decryptor:
    def __init__(self, key="secret", degree=3):
        self.key = key
        self.degree = degree

    def xor_unmix(self, mixed_values):
        """Reverse additive mixing: subtract key values mod-26.
        Perfectly invertible: (a + b) % 26 reverses with (result - b) % 26
        """
        key_vals = [ord(c.upper()) - ord('A') for c in self.key if c.isalpha()]
        if not key_vals:
            key_vals = [0]
        key_len = len(key_vals)
        
        result = []
        for i, val in enumerate(mixed_values):
            unmixed = (val - key_vals[i % key_len]) % 26
            result.append(unmixed)
        return result

    def create_diffusion_graph(self, n):
        """Rebuild graph from key and node count (deterministic from key)."""
        G = nx.Graph()
        rng = random.Random(hash(self.key))

        # Create n nodes
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

    def decrypt(self, encrypted_output):
        print(f"\n{'='*60}")
        print(f"DECRYPTION")
        print(f"{'='*60}")

        # Parse input: "ENCRYPTED_TEXT|length|edges"
        if "|" not in encrypted_output:
            print("ERROR: Invalid format!")
            print("Expected format: ENCRYPTED_TEXT|length|edges")
            print("Example: OMEKE|5|0,2,4;0,3,8;0,4,1;...")
            print("\nYou need the FULL output from encrypt.py!")
            return None
        
        parts = encrypted_output.split("|")
        if len(parts) != 3:
            print("ERROR: Invalid format!")
            print("Expected format: ENCRYPTED_TEXT|length|edges")
            print(f"Got {len(parts)} parts instead of 3")
            return None
            
        encrypted_text = parts[0]
        try:
            text_length = int(parts[1])
        except Exception:
            print("ERROR: Length part is not a valid integer.")
            return None
        edges_data = parts[2]
        
        print(f"Encrypted Text: {encrypted_text}")
        print(f"Text Length: {text_length}")
        
        # Step 1: Reverse XOR mixing first (convert letters to values, unmix)
        encrypted_values = [ord(c) - ord('A') for c in encrypted_text]
        dijkstra_encrypted = self.xor_unmix(encrypted_values)
        print(f"\n=== After reversing XOR ===")
        print(f"Dijkstra-encrypted values: {dijkstra_encrypted}")
        
        # Step 2: Rebuild graph from the edges in the encrypted output (exact same graph!)
        print("\n=== Graph Edges (u, v, weight) ===")
        G = nx.Graph()
        for i in range(text_length):
            G.add_node(i)
        
        for edge_str in edges_data.split(";"):
            u, v, w = map(int, edge_str.split(","))
            G.add_edge(u, v, weight=w)
            print(f"({u}, {v}, {w})")
        
        print(f"\nRebuilt Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
        
        # Step 3: Reverse Single-Source Shortest Path from node 0
        plaintext_values = []
        print("\n=== Dijkstra Decryption (SSSP from Node 0) ===")
        
        # Compute shortest paths from node 0 to all other nodes (same as encryption)
        distances_from_0 = {}
        for target in range(text_length):
            distances_from_0[target] = self.shortest_path_distance(G, 0, target)
        
        # Decrypt each encrypted value
        for i in range(text_length):
            sp_distance = distances_from_0[i]
            encrypted_val = dijkstra_encrypted[i]
            plain_val = (encrypted_val - sp_distance) % 26
            plaintext_values.append(plain_val)
            print(f"  Node 0→{i}: distance={sp_distance}, ({encrypted_val} - {sp_distance}) % 26 = {plain_val}")
        
        print(f"\nRecovered plaintext values: {plaintext_values}")

        # Integrity check: re-encrypt and compare
        re_encrypted = []
        for i in range(text_length):
            sp = distances_from_0[i]
            re_encrypted.append((plaintext_values[i] + sp) % 26)
        re_mixed = [(re_encrypted[i] + (ord(self.key[i % len(self.key)].upper()) - ord('A'))) % 26 for i in range(text_length)]
        re_encrypted_text = "".join([chr(v + ord('A')) for v in re_mixed])
        if re_encrypted_text != encrypted_text:
            print("\nWARNING: Integrity check failed. Possible causes:")
            print("- Wrong key")
            print("- Corrupted input")
            print(f"Recomputed: {re_encrypted_text} vs Input: {encrypted_text}")

        # Convert to plaintext
        plaintext = "".join([chr(v + ord('a')) for v in plaintext_values])
        print(f"\n{'='*60}")
        print(f"Decrypted Word: {plaintext}")
        print(f"{'='*60}")
        
        return plaintext


if __name__ == "__main__":
    # Simulate receiving encrypted data from encrypt.py
    encrypted_output = input("Enter encrypted output: ")
    key = input("Enter key: ")
    
    decryptor = Decryptor(key=key, degree=3)
    plaintext = decryptor.decrypt(encrypted_output)
    
    print(f"\n{'='*60}")
    print(f"RESULT: {plaintext}")
