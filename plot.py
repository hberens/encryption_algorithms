# import matplotlib.pyplot as plt

# # Data (time in ms)
# data = {
#     'Vigenere': {'Encrypt': 20.119, 'Decrypt': 20.056},
#     'AES': {'Encrypt': 2878.938, 'Decrypt': 5821.068},
#     '3DES': {'Encrypt': 9854.751, 'Decrypt': 9798.846},
#     'RSA': {'Encrypt': 67.761, 'Decrypt': 100.039}
# }

# # Create 4 separate plots
# for algo, times in data.items():
#     plt.figure()
    
#     labels = list(times.keys())
#     values = list(times.values())
    
#     plt.bar(labels, values)
    
#     plt.title(f'{algo} - 100KB Test')
#     plt.ylabel('Time (ms)')
#     plt.xlabel('Operation')
    
#     plt.tight_layout()
#     plt.show()

import matplotlib.pyplot as plt

# Average times (ms)
algorithms = ['Vigenere', 'AES', '3DES', 'RSA']
avg_times = [
    (20.119 + 20.056) / 2,
    (2878.938 + 5821.068) / 2,
    (9854.751 + 9798.846) / 2,
    (67.761 + 100.039) / 2
]

plt.figure()

plt.bar(algorithms, avg_times)

plt.title('Average Encryption/Decryption Time (100KB Test)')
plt.xlabel('Algorithm')
plt.ylabel('Time (ms)')

plt.tight_layout()
plt.show()