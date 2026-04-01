import glob
import os

files = glob.glob('agent/analyzers/*.py')
for f in files:
    with open(f, 'r', encoding='utf-8') as file:
        content = file.read()
    content = content.replace('_sorted.log', '.log')
    with open(f, 'w', encoding='utf-8') as file:
        file.write(content)
print('Done!')
