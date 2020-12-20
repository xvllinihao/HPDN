import networkx as nx
import matplotlib.pyplot as plt

G = nx.Graph()
G = nx.cycle_graph(3)

nx.draw(G, with_labels=True)
plt.show()