import glob
import os
import pickle


""" 
This transforms the powershell scripts from https://github.com/das-lab/mpsd
to list of strings and saves them as pickle files. 
"""
paths = {
'raw_pure' : "/home/toaster/dev/mpsd/malicious_pure/",
'raw_mixed' : "/home/toaster/dev/mpsd/mixed_malicious/",
'raw_benign' : "/home/toaster/dev/mpsd/powershell_benign_dataset/",
}
save_path = "./data"
if not os.path.isdir(save_path):
    os.makedirs(save_path)

for name, path in paths.items():
    scripts = []
    for file in glob.glob(path + '*.ps1'):
        with open(file) as f:
            scripts.append(f.read())
    save_file = os.path.join(save_path, name + ".pkl")
    with open(save_file, 'wb') as f:
        pickle.dump(scripts, f)
