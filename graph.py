import networkx as nx

def visualize_graph(G, title=None):
	"""Visualize a NetworkX graph with node labels and edge weights.

	- Nodes show their `label` attribute if present, otherwise the node id
	- Edges show their `weight` attribute
	- Uses a spring layout for clarity

	If matplotlib is not installed, this function prints a helpful message
	and returns without raising an exception.
	"""
	try:
		import matplotlib.pyplot as plt
	except Exception:
		print("Visualization skipped: matplotlib not installed. Run 'pip install matplotlib'.")
		return

	if not isinstance(G, nx.Graph):
		print("Visualization skipped: provided object is not a NetworkX Graph.")
		return

	pos = nx.spring_layout(G, seed=42)

	# Node labels: prefer stored 'label' attribute
	node_labels = {n: (G.nodes[n].get('label', n)) for n in G.nodes}
	edge_labels = nx.get_edge_attributes(G, 'weight')

	plt.figure(figsize=(8, 6))
	if title:
		plt.title(title)

	nx.draw_networkx_nodes(G, pos, node_color="#6baed6", edgecolors="#08519c", linewidths=1.5)
	nx.draw_networkx_edges(G, pos, width=1.5, alpha=0.8)
	nx.draw_networkx_labels(G, pos, labels=node_labels, font_size=10, font_color="#08306b")
	nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=9)

	plt.axis("off")
	plt.tight_layout()
	plt.show()
