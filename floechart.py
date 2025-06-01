from graphviz import Digraph

# Create the flowchart with improved styling
dot = Digraph('DDoS_Methodology', format='png',
              graph_attr={'rankdir': 'TB', 'splines': 'ortho', 'fontname': 'Arial'},
              node_attr={'fontname': 'Arial'})

# ===== 1. Dataset Selection & Preprocessing =====
# Terminator (Start)
dot.node('Start', 'Start: DDoS Detection System', shape='ellipse', color='blue')

# Process nodes
dot.node('A', 'CIC-DDoS2019 Dataset', shape='cylinder', color='blue')
dot.node('B', 'Data Conversion:\nParquet → CSV', shape='rect', color='blue')
dot.node('C', 'Feature Selection', shape='rect', color='blue')
dot.node('C1', 'VarianceThreshold:\nRemove Low-Variance Features', shape='rect', color='blue')
dot.node('C2', 'Recursive Feature Elimination\n(RFE) with XGBoost', shape='rect', color='blue')
dot.node('C3', 'Packet-Level &\nFlow-Based Feature Extraction', shape='rect', color='blue')
dot.node('D', 'Data Normalization:\nStandardScaler', shape='rect', color='blue')
dot.node('E', 'Class Imbalance Handling', shape='hexagon', color='blue')
dot.node('E1', 'SMOTE:\nOversampling Minority Classes', shape='rect', color='blue')
dot.node('E2', 'Cluster-Based\nUndersampling', shape='rect', color='blue')

# Edges for preprocessing
dot.edges([('Start', 'A'), ('A', 'B'), ('B', 'C'), ('C', 'C1'), ('C', 'C2'), ('C', 'C3'),
           ('C', 'D'), ('D', 'E'), ('E', 'E1'), ('E', 'E2')])

# ===== 2. Model Training ===== 
dot.node('F', 'Preprocessed Dataset', shape='parallelogram', color='green')
dot.node('G', 'Model Training', shape='rect', color='green')
dot.node('G2', 'XGBoost Classifier', shape='rect', color='green')
dot.node('H', 'Final Prediction Model', shape='rect', color='green')

# Decision point for model evaluation
dot.node('Eval', 'Model Performance\nAcceptable?', shape='diamond', color='purple')

# Edges for classification
dot.edges([('E2', 'F'), ('F', 'G'), ('G', 'G2'), ('G2', 'H'), ('H', 'Eval')])

# ===== 3. Real-Time System Implementation =====
dot.node('J', 'Live Traffic Capture:\nScapy', shape='rect', color='orange')
dot.node('K', 'Feature Extraction', shape='rect', color='orange')
dot.node('L', 'Apache Kafka:\nReal-Time Streaming', shape='rect', color='orange')
dot.node('M', 'XGBoost Classification', shape='rect', color='orange')
dot.node('N', 'Incremental Learning Updates\n(PA Classifier + SGD)', shape='rect', color='orange')
dot.node('O', 'Alert Generation', shape='rect', color='orange')
dot.node('P', 'Visualization:\nFlask + Plotly Dashboards', shape='parallelogram', color='orange')

# Edges for real-time
dot.edges([('Eval', 'J'), ('J', 'K'), ('K', 'L'), ('L', 'M'), 
           ('M', 'N'), ('N', 'O'), ('O', 'P')])

# ===== 4. Evaluation & Feedback =====
dot.node('Q', 'Confusion Matrix', shape='parallelogram', color='red')
dot.node('R', 'Precision/Recall/F1-Score', shape='rect', color='red')
dot.node('S', 'False Positive Rate (FPR)', shape='rect', color='red')
dot.node('T', 'False Negative Rate (FNR)', shape='rect', color='red')
dot.node('U', 'Model Optimization', shape='hexagon', color='red')

# Terminator (End)
dot.node('End', 'Deployment Feedback Loop', shape='ellipse', color='red')

# Edges for evaluation
dot.edges([('P', 'Q'), ('Q', 'R'), ('Q', 'S'), ('Q', 'T'),
           ('R', 'U'), ('S', 'U'), ('T', 'U'), ('U', 'End')])

# Feedback loop to model training
dot.edge('U', 'G', style='dashed', color='purple')

# Rejection path from evaluation
dot.edge('Eval', 'G', label='No', style='dashed', color='red')

# ===== Formatting =====
dot.attr(label='Figure 3.1: Optimized DDoS Detection Methodology\n(XGBoost + Incremental Learning)',
         labelloc='t', fontsize='14')

# Add legend
with dot.subgraph(name='cluster_legend') as legend:
    legend.attr(label='Legend', style='rounded', color='gray')
    legend.node('L1', 'Start/End', shape='ellipse')
    legend.node('L2', 'Process', shape='rect')
    legend.node('L3', 'Decision', shape='diamond')
    legend.node('L4', 'Data', shape='parallelogram')
    legend.node('L5', 'Database', shape='cylinder')
    legend.node('L6', 'Preparation', shape='hexagon')
    legend.attr(rank='same')

# Save and render
dot.render('DDoS_Methodology_Optimized', view=True, cleanup=True)
print("Optimized flowchart generated as 'DDoS_Methodology_Optimized.png'")