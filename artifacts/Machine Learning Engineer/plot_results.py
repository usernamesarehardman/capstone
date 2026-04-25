import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt

# Load the matrix
df = pd.read_csv('confusion_matrix.csv', index_col=0)

# Set up the plot
plt.figure(figsize=(18, 12))
sns.heatmap(df, annot=False, cmap='YlGnBu', cbar=True)

plt.title('Website Fingerprinting: Confusion Matrix Heatmap', fontsize=16)
plt.xlabel('Predicted Website', fontsize=12)
plt.ylabel('Actual Website', fontsize=12)

# Save it for your report
plt.tight_layout()
plt.savefig('confusion_heatmap.png', dpi=300)
print("[+] Heatmap saved as 'confusion_heatmap.png'")
plt.show()